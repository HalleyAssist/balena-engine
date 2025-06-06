package system // import "github.com/docker/docker/api/server/router/system"

import (
	"github.com/docker/docker/api/server/router"
)

// systemRouter provides information about the Docker system overall.
// It gathers information about host, daemon and container events.
type systemRouter struct {
	backend  Backend
	cluster  ClusterBackend
	routes   []router.Route
	features *map[string]bool
}

// NewRouter initializes a new system router
func NewRouter(b Backend, c ClusterBackend, features *map[string]bool) router.Router {
	r := &systemRouter{
		backend:  b,
		cluster:  c,
		features: features,
	}

	r.routes = []router.Route{
		router.NewOptionsRoute("/{anyroute:.*}", optionsHandler),
		router.NewGetRoute("/_ping", r.pingHandler),
		router.NewHeadRoute("/_ping", r.pingHandler),
		router.NewGetRoute("/events", r.getEvents),
		router.NewGetRoute("/info", r.getInfo),
		router.NewGetRoute("/version", r.getVersion),
		router.NewGetRoute("/system/df", r.getDiskUsage),
		router.NewPostRoute("/auth", r.postAuth),
	}

	return r
}

// Routes returns all the API routes dedicated to the docker system
func (s *systemRouter) Routes() []router.Route {
	return s.routes
}
