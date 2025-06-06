package command

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	cliconfig "github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	dcontext "github.com/docker/cli/cli/context"
	"github.com/docker/cli/cli/context/docker"
	"github.com/docker/cli/cli/context/store"
	"github.com/docker/cli/cli/debug"
	cliflags "github.com/docker/cli/cli/flags"
	manifeststore "github.com/docker/cli/cli/manifest/store"
	registryclient "github.com/docker/cli/cli/registry/client"
	"github.com/docker/cli/cli/streams"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/cli/version"
	dopts "github.com/docker/cli/opts"
	"github.com/docker/docker/api"
	"github.com/docker/docker/api/types"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/moby/term"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/notary"
	notaryclient "github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/passphrase"
)

// Streams is an interface which exposes the standard input and output streams
type Streams interface {
	In() *streams.In
	Out() *streams.Out
	Err() io.Writer
}

// Cli represents the docker command line client.
type Cli interface {
	Client() client.APIClient
	Out() *streams.Out
	Err() io.Writer
	In() *streams.In
	SetIn(in *streams.In)
	Apply(ops ...DockerCliOption) error
	ConfigFile() *configfile.ConfigFile
	ServerInfo() ServerInfo
	ClientInfo() ClientInfo
	NotaryClient(imgRefAndAuth trust.ImageRefAndAuth, actions []string) (notaryclient.Repository, error)
	DefaultVersion() string
	ManifestStore() manifeststore.Store
	RegistryClient(bool) registryclient.RegistryClient
	ContentTrustEnabled() bool
	ContextStore() store.Store
	CurrentContext() string
	StackOrchestrator(flagValue string) (Orchestrator, error)
	DockerEndpoint() docker.Endpoint
}

// DockerCli is an instance the docker command line client.
// Instances of the client can be returned from NewDockerCli.
type DockerCli struct {
	configFile         *configfile.ConfigFile
	in                 *streams.In
	out                *streams.Out
	err                io.Writer
	client             client.APIClient
	serverInfo         ServerInfo
	clientInfo         *ClientInfo
	contentTrust       bool
	contextStore       store.Store
	currentContext     string
	dockerEndpoint     docker.Endpoint
	contextStoreConfig store.Config
}

// DefaultVersion returns api.defaultVersion or DOCKER_API_VERSION if specified.
func (cli *DockerCli) DefaultVersion() string {
	return cli.ClientInfo().DefaultVersion
}

// Client returns the APIClient
func (cli *DockerCli) Client() client.APIClient {
	return cli.client
}

// Out returns the writer used for stdout
func (cli *DockerCli) Out() *streams.Out {
	return cli.out
}

// Err returns the writer used for stderr
func (cli *DockerCli) Err() io.Writer {
	return cli.err
}

// SetIn sets the reader used for stdin
func (cli *DockerCli) SetIn(in *streams.In) {
	cli.in = in
}

// In returns the reader used for stdin
func (cli *DockerCli) In() *streams.In {
	return cli.in
}

// ShowHelp shows the command help.
func ShowHelp(err io.Writer) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		cmd.SetOut(err)
		cmd.HelpFunc()(cmd, args)
		return nil
	}
}

// ConfigFile returns the ConfigFile
func (cli *DockerCli) ConfigFile() *configfile.ConfigFile {
	if cli.configFile == nil {
		cli.loadConfigFile()
	}
	return cli.configFile
}

func (cli *DockerCli) loadConfigFile() {
	cli.configFile = cliconfig.LoadDefaultConfigFile(cli.err)
}

// ServerInfo returns the server version details for the host this client is
// connected to
func (cli *DockerCli) ServerInfo() ServerInfo {
	return cli.serverInfo
}

// ClientInfo returns the client details for the cli
func (cli *DockerCli) ClientInfo() ClientInfo {
	if cli.clientInfo == nil {
		if err := cli.loadClientInfo(); err != nil {
			panic(err)
		}
	}
	return *cli.clientInfo
}

func (cli *DockerCli) loadClientInfo() error {
	var v string
	if cli.client != nil {
		v = cli.client.ClientVersion()
	} else {
		v = api.DefaultVersion
	}
	cli.clientInfo = &ClientInfo{
		DefaultVersion:  v,
		HasExperimental: true,
	}
	return nil
}

// ContentTrustEnabled returns whether content trust has been enabled by an
// environment variable.
func (cli *DockerCli) ContentTrustEnabled() bool {
	return cli.contentTrust
}

// ManifestStore returns a store for local manifests
func (cli *DockerCli) ManifestStore() manifeststore.Store {
	// TODO: support override default location from config file
	return manifeststore.NewStore(filepath.Join(config.Dir(), "manifests"))
}

// RegistryClient returns a client for communicating with a Docker distribution
// registry
func (cli *DockerCli) RegistryClient(allowInsecure bool) registryclient.RegistryClient {
	resolver := func(ctx context.Context, index *registrytypes.IndexInfo) types.AuthConfig {
		return ResolveAuthConfig(ctx, cli, index)
	}
	return registryclient.NewRegistryClient(resolver, UserAgent(), allowInsecure)
}

// InitializeOpt is the type of the functional options passed to DockerCli.Initialize
type InitializeOpt func(dockerCli *DockerCli) error

// WithInitializeClient is passed to DockerCli.Initialize by callers who wish to set a particular API Client for use by the CLI.
func WithInitializeClient(makeClient func(dockerCli *DockerCli) (client.APIClient, error)) InitializeOpt {
	return func(dockerCli *DockerCli) error {
		var err error
		dockerCli.client, err = makeClient(dockerCli)
		return err
	}
}

// Initialize the dockerCli runs initialization that must happen after command
// line flags are parsed.
func (cli *DockerCli) Initialize(opts *cliflags.ClientOptions, ops ...InitializeOpt) error {
	var err error

	for _, o := range ops {
		if err := o(cli); err != nil {
			return err
		}
	}
	cliflags.SetLogLevel(opts.Common.LogLevel)

	if opts.ConfigDir != "" {
		cliconfig.SetDir(opts.ConfigDir)
	}

	if opts.Common.Debug {
		debug.Enable()
	}

	cli.loadConfigFile()

	baseContextStore := store.New(cliconfig.ContextStoreDir(), cli.contextStoreConfig)
	cli.contextStore = &ContextStoreWithDefault{
		Store: baseContextStore,
		Resolver: func() (*DefaultContext, error) {
			return ResolveDefaultContext(opts.Common, cli.ConfigFile(), cli.contextStoreConfig, cli.Err())
		},
	}
	cli.currentContext, err = resolveContextName(opts.Common, cli.configFile, cli.contextStore)
	if err != nil {
		return err
	}
	cli.dockerEndpoint, err = resolveDockerEndpoint(cli.contextStore, cli.currentContext)
	if err != nil {
		return errors.Wrap(err, "unable to resolve docker endpoint")
	}

	if cli.client == nil {
		cli.client, err = newAPIClientFromEndpoint(cli.dockerEndpoint, cli.configFile)
		if tlsconfig.IsErrEncryptedKey(err) {
			passRetriever := passphrase.PromptRetrieverWithInOut(cli.In(), cli.Out(), nil)
			newClient := func(password string) (client.APIClient, error) {
				cli.dockerEndpoint.TLSPassword = password //nolint: staticcheck // SA1019: cli.dockerEndpoint.TLSPassword is deprecated
				return newAPIClientFromEndpoint(cli.dockerEndpoint, cli.configFile)
			}
			cli.client, err = getClientWithPassword(passRetriever, newClient)
		}
		if err != nil {
			return err
		}
	}
	cli.initializeFromClient()

	if err := cli.loadClientInfo(); err != nil {
		return err
	}

	return nil
}

// NewAPIClientFromFlags creates a new APIClient from command line flags
func NewAPIClientFromFlags(opts *cliflags.CommonOptions, configFile *configfile.ConfigFile) (client.APIClient, error) {
	storeConfig := DefaultContextStoreConfig()
	store := &ContextStoreWithDefault{
		Store: store.New(cliconfig.ContextStoreDir(), storeConfig),
		Resolver: func() (*DefaultContext, error) {
			return ResolveDefaultContext(opts, configFile, storeConfig, ioutil.Discard)
		},
	}
	contextName, err := resolveContextName(opts, configFile, store)
	if err != nil {
		return nil, err
	}
	endpoint, err := resolveDockerEndpoint(store, contextName)
	if err != nil {
		return nil, errors.Wrap(err, "unable to resolve docker endpoint")
	}
	return newAPIClientFromEndpoint(endpoint, configFile)
}

func newAPIClientFromEndpoint(ep docker.Endpoint, configFile *configfile.ConfigFile) (client.APIClient, error) {
	clientOpts, err := ep.ClientOpts()
	if err != nil {
		return nil, err
	}
	customHeaders := make(map[string]string, len(configFile.HTTPHeaders))
	for k, v := range configFile.HTTPHeaders {
		customHeaders[k] = v
	}
	customHeaders["User-Agent"] = UserAgent()
	clientOpts = append(clientOpts, client.WithHTTPHeaders(customHeaders))
	return client.NewClientWithOpts(clientOpts...)
}

func resolveDockerEndpoint(s store.Reader, contextName string) (docker.Endpoint, error) {
	ctxMeta, err := s.GetMetadata(contextName)
	if err != nil {
		return docker.Endpoint{}, err
	}
	epMeta, err := docker.EndpointFromContext(ctxMeta)
	if err != nil {
		return docker.Endpoint{}, err
	}
	return docker.WithTLSData(s, contextName, epMeta)
}

// Resolve the Docker endpoint for the default context (based on config, env vars and CLI flags)
func resolveDefaultDockerEndpoint(opts *cliflags.CommonOptions) (docker.Endpoint, error) {
	host, err := getServerHost(opts.Hosts, opts.TLSOptions)
	if err != nil {
		return docker.Endpoint{}, err
	}

	var (
		skipTLSVerify bool
		tlsData       *dcontext.TLSData
	)

	if opts.TLSOptions != nil {
		skipTLSVerify = opts.TLSOptions.InsecureSkipVerify
		tlsData, err = dcontext.TLSDataFromFiles(opts.TLSOptions.CAFile, opts.TLSOptions.CertFile, opts.TLSOptions.KeyFile)
		if err != nil {
			return docker.Endpoint{}, err
		}
	}

	return docker.Endpoint{
		EndpointMeta: docker.EndpointMeta{
			Host:          host,
			SkipTLSVerify: skipTLSVerify,
		},
		TLSData: tlsData,
	}, nil
}

func (cli *DockerCli) initializeFromClient() {
	ctx := context.Background()
	if strings.HasPrefix(cli.DockerEndpoint().Host, "tcp://") {
		// @FIXME context.WithTimeout doesn't work with connhelper / ssh connections
		// time="2020-04-10T10:16:26Z" level=warning msg="commandConn.CloseWrite: commandconn: failed to wait: signal: killed"
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}

	ping, err := cli.client.Ping(ctx)
	if err != nil {
		// Default to true if we fail to connect to daemon
		cli.serverInfo = ServerInfo{HasExperimental: true}

		if ping.APIVersion != "" {
			cli.client.NegotiateAPIVersionPing(ping)
		}
		return
	}

	cli.serverInfo = ServerInfo{
		HasExperimental: ping.Experimental,
		OSType:          ping.OSType,
		BuildkitVersion: ping.BuilderVersion,
	}
	cli.client.NegotiateAPIVersionPing(ping)
}

func getClientWithPassword(passRetriever notary.PassRetriever, newClient func(password string) (client.APIClient, error)) (client.APIClient, error) {
	for attempts := 0; ; attempts++ {
		passwd, giveup, err := passRetriever("private", "encrypted TLS private", false, attempts)
		if giveup || err != nil {
			return nil, errors.Wrap(err, "private key is encrypted, but could not get passphrase")
		}

		apiclient, err := newClient(passwd)
		if !tlsconfig.IsErrEncryptedKey(err) {
			return apiclient, err
		}
	}
}

// NotaryClient provides a Notary Repository to interact with signed metadata for an image
func (cli *DockerCli) NotaryClient(imgRefAndAuth trust.ImageRefAndAuth, actions []string) (notaryclient.Repository, error) {
	return trust.GetNotaryRepository(cli.In(), cli.Out(), UserAgent(), imgRefAndAuth.RepoInfo(), imgRefAndAuth.AuthConfig(), actions...)
}

// ContextStore returns the ContextStore
func (cli *DockerCli) ContextStore() store.Store {
	return cli.contextStore
}

// CurrentContext returns the current context name
func (cli *DockerCli) CurrentContext() string {
	return cli.currentContext
}

// StackOrchestrator resolves which stack orchestrator is in use
func (cli *DockerCli) StackOrchestrator(flagValue string) (Orchestrator, error) {
	currentContext := cli.CurrentContext()
	ctxRaw, err := cli.ContextStore().GetMetadata(currentContext)
	if store.IsErrContextDoesNotExist(err) {
		// case where the currentContext has been removed (CLI behavior is to fallback to using DOCKER_HOST based resolution)
		return GetStackOrchestrator(flagValue, "", cli.ConfigFile().StackOrchestrator, cli.Err())
	}
	if err != nil {
		return "", err
	}
	ctxMeta, err := GetDockerContext(ctxRaw)
	if err != nil {
		return "", err
	}
	ctxOrchestrator := string(ctxMeta.StackOrchestrator)
	return GetStackOrchestrator(flagValue, ctxOrchestrator, cli.ConfigFile().StackOrchestrator, cli.Err())
}

// DockerEndpoint returns the current docker endpoint
func (cli *DockerCli) DockerEndpoint() docker.Endpoint {
	return cli.dockerEndpoint
}

// Apply all the operation on the cli
func (cli *DockerCli) Apply(ops ...DockerCliOption) error {
	for _, op := range ops {
		if err := op(cli); err != nil {
			return err
		}
	}
	return nil
}

// ServerInfo stores details about the supported features and platform of the
// server
type ServerInfo struct {
	HasExperimental bool
	OSType          string
	BuildkitVersion types.BuilderVersion
}

// ClientInfo stores details about the supported features of the client
type ClientInfo struct {
	// Deprecated: experimental CLI features always enabled. This field is kept
	// for backward-compatibility, and is always "true".
	HasExperimental bool
	DefaultVersion  string
}

// NewDockerCli returns a DockerCli instance with all operators applied on it.
// It applies by default the standard streams, and the content trust from
// environment.
func NewDockerCli(ops ...DockerCliOption) (*DockerCli, error) {
	cli := &DockerCli{}
	defaultOps := []DockerCliOption{
		WithContentTrustFromEnv(),
	}
	cli.contextStoreConfig = DefaultContextStoreConfig()
	ops = append(defaultOps, ops...)
	if err := cli.Apply(ops...); err != nil {
		return nil, err
	}
	if cli.out == nil || cli.in == nil || cli.err == nil {
		stdin, stdout, stderr := term.StdStreams()
		if cli.in == nil {
			cli.in = streams.NewIn(stdin)
		}
		if cli.out == nil {
			cli.out = streams.NewOut(stdout)
		}
		if cli.err == nil {
			cli.err = stderr
		}
	}
	return cli, nil
}

func getServerHost(hosts []string, tlsOptions *tlsconfig.Options) (string, error) {
	var host string
	switch len(hosts) {
	case 0:
		host = os.Getenv("DOCKER_HOST")
	case 1:
		host = hosts[0]
	default:
		return "", errors.New("Please specify only one -H")
	}

	return dopts.ParseHost(tlsOptions != nil, host)
}

// UserAgent returns the user agent string used for making API requests
func UserAgent() string {
	return "Docker-Client/" + version.Version + " (" + runtime.GOOS + ")"
}

// resolveContextName resolves the current context name with the following rules:
// - setting both --context and --host flags is ambiguous
// - if --context is set, use this value
// - if --host flag or DOCKER_HOST is set, fallbacks to use the same logic as before context-store was added
// for backward compatibility with existing scripts
// - if DOCKER_CONTEXT is set, use this value
// - if Config file has a globally set "CurrentContext", use this value
// - fallbacks to default HOST, uses TLS config from flags/env vars
func resolveContextName(opts *cliflags.CommonOptions, config *configfile.ConfigFile, contextstore store.Reader) (string, error) {
	if opts.Context != "" && len(opts.Hosts) > 0 {
		return "", errors.New("Conflicting options: either specify --host or --context, not both")
	}
	if opts.Context != "" {
		return opts.Context, nil
	}
	if len(opts.Hosts) > 0 {
		return DefaultContextName, nil
	}
	if _, present := os.LookupEnv("DOCKER_HOST"); present {
		return DefaultContextName, nil
	}
	if ctxName, ok := os.LookupEnv("DOCKER_CONTEXT"); ok {
		return ctxName, nil
	}
	if config != nil && config.CurrentContext != "" {
		_, err := contextstore.GetMetadata(config.CurrentContext)
		if store.IsErrContextDoesNotExist(err) {
			return "", errors.Errorf("Current context %q is not found on the file system, please check your config file at %s", config.CurrentContext, config.Filename)
		}
		return config.CurrentContext, err
	}
	return DefaultContextName, nil
}

var defaultStoreEndpoints = []store.NamedTypeGetter{
	store.EndpointTypeGetter(docker.DockerEndpoint, func() interface{} { return &docker.EndpointMeta{} }),
}

// RegisterDefaultStoreEndpoints registers a new named endpoint
// metadata type with the default context store config, so that
// endpoint will be supported by stores using the config returned by
// DefaultContextStoreConfig.
func RegisterDefaultStoreEndpoints(ep ...store.NamedTypeGetter) {
	defaultStoreEndpoints = append(defaultStoreEndpoints, ep...)
}

// DefaultContextStoreConfig returns a new store.Config with the default set of endpoints configured.
func DefaultContextStoreConfig() store.Config {
	return store.NewConfig(
		func() interface{} { return &DockerContext{} },
		defaultStoreEndpoints...,
	)
}
