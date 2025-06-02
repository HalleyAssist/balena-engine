package daemon // import "github.com/docker/docker/daemon"

import (
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/capabilities"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type deviceDriver struct {
	capset     capabilities.Set
	updateSpec func(*specs.Spec, *deviceInstance) error
}

type deviceInstance struct {
	req          container.DeviceRequest
	selectedCaps []string
}

func (daemon *Daemon) handleDevice(req container.DeviceRequest, spec *specs.Spec) error {
	return incompatibleDeviceRequest{req.Driver, req.Capabilities}
}
