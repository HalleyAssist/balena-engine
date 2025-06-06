package resolver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	distreference "github.com/docker/distribution/reference"
	"github.com/moby/buildkit/session"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// DefaultPool is the default shared resolver pool instance
var DefaultPool = NewPool()

// Pool is a cache of recently used resolvers
type Pool struct {
	mu sync.Mutex
	m  map[string]*authHandlerNS
}

// NewPool creates a new pool for caching resolvers
func NewPool() *Pool {
	p := &Pool{
		m: map[string]*authHandlerNS{},
	}
	time.AfterFunc(5*time.Minute, p.gc)
	return p
}

func (p *Pool) gc() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for k, ns := range p.m {
		ns.mu.Lock()
		for key, h := range ns.handlers {
			if time.Since(h.lastUsed) < 10*time.Minute {
				continue
			}
			parts := strings.SplitN(key, "/", 2)
			if len(parts) != 2 {
				delete(ns.handlers, key)
				continue
			}
			c, err := ns.sm.Get(context.TODO(), parts[1], true)
			if c == nil || err != nil {
				delete(ns.handlers, key)
			}
		}
		if len(ns.handlers) == 0 {
			delete(p.m, k)
		}
		ns.mu.Unlock()
	}

	time.AfterFunc(5*time.Minute, p.gc)
}

// Clear deletes currently cached items. This may be called on config changes for example.
func (p *Pool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m = map[string]*authHandlerNS{}
}

// GetResolver gets a resolver for a specified scope from the pool
func (p *Pool) GetResolver(hosts docker.RegistryHosts, ref, scope string, sm *session.Manager, g session.Group) *Resolver {
	name := ref
	named, err := distreference.ParseNormalizedNamed(ref)
	if err == nil {
		name = named.Name()
	}

	key := fmt.Sprintf("%s::%s", name, scope)

	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.m[key]
	if !ok {
		h = newAuthHandlerNS(sm)
		p.m[key] = h
	}
	return newResolver(hosts, h, sm, g)
}

func newResolver(hosts docker.RegistryHosts, handler *authHandlerNS, sm *session.Manager, g session.Group) *Resolver {
	if hosts == nil {
		hosts = docker.ConfigureDefaultRegistries(
			docker.WithClient(newDefaultClient()),
			docker.WithPlainHTTP(docker.MatchLocalhost),
		)
	}
	r := &Resolver{
		hosts:   hosts,
		sm:      sm,
		g:       g,
		handler: handler,
	}
	r.Resolver = docker.NewResolver(docker.ResolverOptions{
		Hosts: r.hostsFunc,
	})
	return r
}

// Resolver is a wrapper around remotes.Resolver
type Resolver struct {
	remotes.Resolver
	hosts   docker.RegistryHosts
	sm      *session.Manager
	g       session.Group
	handler *authHandlerNS
	auth    *dockerAuthorizer

	is images.Store
}

func (r *Resolver) hostsFunc(host string) ([]docker.RegistryHost, error) {
	return func(domain string) ([]docker.RegistryHost, error) {
		v, err := r.handler.g.Do(context.TODO(), domain, func(ctx context.Context) (interface{}, error) {
			// long lock not needed because flightcontrol.Do
			r.handler.mu.Lock()
			v, ok := r.handler.hosts[domain]
			r.handler.mu.Unlock()
			if ok {
				return v, nil
			}
			res, err := r.hosts(domain)
			if err != nil {
				return nil, err
			}
			r.handler.mu.Lock()
			r.handler.hosts[domain] = res
			r.handler.mu.Unlock()
			return res, nil
		})
		if err != nil || v == nil {
			return nil, err
		}
		res := v.([]docker.RegistryHost)
		if len(res) == 0 {
			return nil, nil
		}
		auth := newDockerAuthorizer(res[0].Client, r.handler, r.sm, r.g)
		for i := range res {
			res[i].Authorizer = auth
		}
		return res, nil
	}(host)
}

// Fetcher returns a new fetcher for the provided reference.
func (r *Resolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	if atomic.LoadInt64(&r.handler.counter) == 0 {
		r.Resolve(ctx, ref)
	}
	return r.Resolver.Fetcher(ctx, ref)
}

// Resolve attempts to resolve the reference into a name and descriptor.
func (r *Resolver) Resolve(ctx context.Context, ref string) (string, ocispec.Descriptor, error) {
	n, desc, err := r.Resolver.Resolve(ctx, ref)
	if err == nil {
		atomic.AddInt64(&r.handler.counter, 1)
		return n, desc, err
	}

	if r.is != nil {
		if img, err := r.is.Get(ctx, ref); err == nil {
			return ref, img.Target, nil
		}
	}

	return "", ocispec.Descriptor{}, err
}
