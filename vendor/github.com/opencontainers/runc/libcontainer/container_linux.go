package libcontainer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
)

const stdioFdCount = 3

type linuxContainer struct {
	id                   string
	root                 string
	config               *configs.Config
	cgroupManager        cgroups.Manager
	intelRdtManager      *intelrdt.Manager
	initPath             string
	initArgs             []string
	initProcess          parentProcess
	initProcessStartTime uint64
	criuPath             string
	newuidmapPath        string
	newgidmapPath        string
	m                    sync.Mutex
	criuVersion          int
	state                containerState
	created              time.Time
	fifo                 *os.File
}

// State represents a running container's state
type State struct {
	BaseState

	// Platform specific fields below here

	// Specified if the container was started under the rootless mode.
	// Set to true if BaseState.Config.RootlessEUID && BaseState.Config.RootlessCgroups
	Rootless bool `json:"rootless"`

	// Paths to all the container's cgroups, as returned by (*cgroups.Manager).GetPaths
	//
	// For cgroup v1, a key is cgroup subsystem name, and the value is the path
	// to the cgroup for this subsystem.
	//
	// For cgroup v2 unified hierarchy, a key is "", and the value is the unified path.
	CgroupPaths map[string]string `json:"cgroup_paths"`

	// NamespacePaths are filepaths to the container's namespaces. Key is the namespace type
	// with the value as the path.
	NamespacePaths map[configs.NamespaceType]string `json:"namespace_paths"`

	// Container's standard descriptors (std{in,out,err}), needed for checkpoint and restore
	ExternalDescriptors []string `json:"external_descriptors,omitempty"`

	// Intel RDT "resource control" filesystem path
	IntelRdtPath string `json:"intel_rdt_path"`
}

// Container is a libcontainer container object.
//
// Each container is thread-safe within the same process. Since a container can
// be destroyed by a separate process, any function may return that the container
// was not found.
type Container interface {
	BaseContainer

	// Methods below here are platform specific

	// Checkpoint checkpoints the running container's state to disk using the criu(8) utility.
	Checkpoint(criuOpts *CriuOpts) error

	// Restore restores the checkpointed container to a running state using the criu(8) utility.
	Restore(process *Process, criuOpts *CriuOpts) error

	// If the Container state is RUNNING or CREATED, sets the Container state to PAUSING and pauses
	// the execution of any user processes. Asynchronously, when the container finished being paused the
	// state is changed to PAUSED.
	// If the Container state is PAUSED, do nothing.
	Pause() error

	// If the Container state is PAUSED, resumes the execution of any user processes in the
	// Container before setting the Container state to RUNNING.
	// If the Container state is RUNNING, do nothing.
	Resume() error

	// NotifyOOM returns a read-only channel signaling when the container receives an OOM notification.
	NotifyOOM() (<-chan struct{}, error)

	// NotifyMemoryPressure returns a read-only channel signaling when the container reaches a given pressure level
	NotifyMemoryPressure(level PressureLevel) (<-chan struct{}, error)
}

// ID returns the container's unique ID
func (c *linuxContainer) ID() string {
	return c.id
}

// Config returns the container's configuration
func (c *linuxContainer) Config() configs.Config {
	return *c.config
}

func (c *linuxContainer) Status() (Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

func (c *linuxContainer) State() (*State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState()
}

func (c *linuxContainer) OCIState() (*specs.State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentOCIState()
}

// ignoreCgroupError filters out cgroup-related errors that can be ignored,
// because the container is stopped and its cgroup is gone.
func (c *linuxContainer) ignoreCgroupError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) && c.runType() == Stopped && !c.cgroupManager.Exists() {
		return nil
	}
	return err
}

func (c *linuxContainer) Processes() ([]int, error) {
	pids, err := c.cgroupManager.GetAllPids()
	if err = c.ignoreCgroupError(err); err != nil {
		return nil, fmt.Errorf("unable to get all container pids: %w", err)
	}
	return pids, nil
}

func (c *linuxContainer) Stats() (*Stats, error) {
	var (
		err   error
		stats = &Stats{}
	)
	if stats.CgroupStats, err = c.cgroupManager.GetStats(); err != nil {
		return stats, fmt.Errorf("unable to get container cgroup stats: %w", err)
	}
	if c.intelRdtManager != nil {
		if stats.IntelRdtStats, err = c.intelRdtManager.GetStats(); err != nil {
			return stats, fmt.Errorf("unable to get container Intel RDT stats: %w", err)
		}
	}
	for _, iface := range c.config.Networks {
		switch iface.Type {
		case "veth":
			istats, err := getNetworkInterfaceStats(iface.HostInterfaceName)
			if err != nil {
				return stats, fmt.Errorf("unable to get network stats for interface %q: %w", iface.HostInterfaceName, err)
			}
			stats.Interfaces = append(stats.Interfaces, istats)
		}
	}
	return stats, nil
}

func (c *linuxContainer) Set(config configs.Config) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status == Stopped {
		return ErrNotRunning
	}
	if err := c.cgroupManager.Set(config.Cgroups.Resources); err != nil {
		// Set configs back
		if err2 := c.cgroupManager.Set(c.config.Cgroups.Resources); err2 != nil {
			logrus.Warnf("Setting back cgroup configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
		}
		return err
	}
	if c.intelRdtManager != nil {
		if err := c.intelRdtManager.Set(&config); err != nil {
			// Set configs back
			if err2 := c.cgroupManager.Set(c.config.Cgroups.Resources); err2 != nil {
				logrus.Warnf("Setting back cgroup configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
			}
			if err2 := c.intelRdtManager.Set(c.config); err2 != nil {
				logrus.Warnf("Setting back intelrdt configs failed due to error: %v, your state.json and actual configs might be inconsistent.", err2)
			}
			return err
		}
	}
	// After config setting succeed, update config and states
	c.config = &config
	_, err = c.updateState(nil)
	return err
}

func (c *linuxContainer) Start(process *Process) error {
	c.m.Lock()
	defer c.m.Unlock()
	if c.config.Cgroups.Resources.SkipDevices {
		return errors.New("can't start container with SkipDevices set")
	}
	if process.Init {
		if err := c.createExecFifo(); err != nil {
			return err
		}
	}
	if err := c.start(process); err != nil {
		if process.Init {
			c.deleteExecFifo()
		}
		return err
	}
	return nil
}

func (c *linuxContainer) Run(process *Process) error {
	if err := c.Start(process); err != nil {
		return err
	}
	if process.Init {
		return c.exec()
	}
	return nil
}

func (c *linuxContainer) Exec() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.exec()
}

func (c *linuxContainer) exec() error {
	path := filepath.Join(c.root, execFifoFilename)
	pid := c.initProcess.pid()
	blockingFifoOpenCh := awaitFifoOpen(path)
	for {
		select {
		case result := <-blockingFifoOpenCh:
			return handleFifoResult(result)

		case <-time.After(time.Millisecond * 100):
			stat, err := system.Stat(pid)
			if err != nil || stat.State == system.Zombie {
				// could be because process started, ran, and completed between our 100ms timeout and our system.Stat() check.
				// see if the fifo exists and has data (with a non-blocking open, which will succeed if the writing process is complete).
				if err := handleFifoResult(fifoOpen(path, false)); err != nil {
					return errors.New("container process is already dead")
				}
				return nil
			}
		}
	}
}

func readFromExecFifo(execFifo io.Reader) error {
	data, err := io.ReadAll(execFifo)
	if err != nil {
		return err
	}
	if len(data) <= 0 {
		return errors.New("cannot start an already running container")
	}
	return nil
}

func awaitFifoOpen(path string) <-chan openResult {
	fifoOpened := make(chan openResult)
	go func() {
		result := fifoOpen(path, true)
		fifoOpened <- result
	}()
	return fifoOpened
}

func fifoOpen(path string, block bool) openResult {
	flags := os.O_RDONLY
	if !block {
		flags |= unix.O_NONBLOCK
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return openResult{err: fmt.Errorf("exec fifo: %w", err)}
	}
	return openResult{file: f}
}

func handleFifoResult(result openResult) error {
	if result.err != nil {
		return result.err
	}
	f := result.file
	defer f.Close()
	if err := readFromExecFifo(f); err != nil {
		return err
	}
	return os.Remove(f.Name())
}

type openResult struct {
	file *os.File
	err  error
}

func (c *linuxContainer) start(process *Process) (retErr error) {
	parent, err := c.newParentProcess(process)
	if err != nil {
		return fmt.Errorf("unable to create new parent process: %w", err)
	}

	logsDone := parent.forwardChildLogs()
	if logsDone != nil {
		defer func() {
			// Wait for log forwarder to finish. This depends on
			// runc init closing the _LIBCONTAINER_LOGPIPE log fd.
			err := <-logsDone
			if err != nil && retErr == nil {
				retErr = fmt.Errorf("unable to forward init logs: %w", err)
			}
		}()
	}

	// Before starting "runc init", mark all non-stdio open files as O_CLOEXEC
	// to make sure we don't leak any files into "runc init". Any files to be
	// passed to "runc init" through ExtraFiles will get dup2'd by the Go
	// runtime and thus their O_CLOEXEC flag will be cleared. This is some
	// additional protection against attacks like CVE-2024-21626, by making
	// sure we never leak files to "runc init" we didn't intend to.
	if err := utils.CloseExecFrom(3); err != nil {
		return fmt.Errorf("unable to mark non-stdio fds as cloexec: %w", err)
	}
	if err := parent.start(); err != nil {
		return fmt.Errorf("unable to start container process: %w", err)
	}

	if process.Init {
		c.fifo.Close()
		if c.config.Hooks != nil {
			s, err := c.currentOCIState()
			if err != nil {
				return err
			}

			if err := c.config.Hooks[configs.Poststart].RunHooks(s); err != nil {
				if err := ignoreTerminateErrors(parent.terminate()); err != nil {
					logrus.Warn(fmt.Errorf("error running poststart hook: %w", err))
				}
				return err
			}
		}
	}
	return nil
}

func (c *linuxContainer) Signal(s os.Signal, all bool) error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if all {
		if status == Stopped && !c.cgroupManager.Exists() {
			// Avoid calling signalAllProcesses which may print
			// a warning trying to freeze a non-existing cgroup.
			return nil
		}
		return c.ignoreCgroupError(signalAllProcesses(c.cgroupManager, s))
	}
	// to avoid a PID reuse attack
	if status == Running || status == Created || status == Paused {
		if err := c.initProcess.signal(s); err != nil {
			return fmt.Errorf("unable to signal init: %w", err)
		}
		if status == Paused {
			// For cgroup v1, killing a process in a frozen cgroup
			// does nothing until it's thawed. Only thaw the cgroup
			// for SIGKILL.
			if s, ok := s.(unix.Signal); ok && s == unix.SIGKILL {
				_ = c.cgroupManager.Freeze(configs.Thawed)
			}
		}
		return nil
	}
	return ErrNotRunning
}

func (c *linuxContainer) createExecFifo() error {
	rootuid, err := c.Config().HostRootUID()
	if err != nil {
		return err
	}
	rootgid, err := c.Config().HostRootGID()
	if err != nil {
		return err
	}

	fifoName := filepath.Join(c.root, execFifoFilename)
	if _, err := os.Stat(fifoName); err == nil {
		return fmt.Errorf("exec fifo %s already exists", fifoName)
	}
	oldMask := unix.Umask(0o000)
	if err := unix.Mkfifo(fifoName, 0o622); err != nil {
		unix.Umask(oldMask)
		return err
	}
	unix.Umask(oldMask)
	return os.Chown(fifoName, rootuid, rootgid)
}

func (c *linuxContainer) deleteExecFifo() {
	fifoName := filepath.Join(c.root, execFifoFilename)
	os.Remove(fifoName)
}

// includeExecFifo opens the container's execfifo as a pathfd, so that the
// container cannot access the statedir (and the FIFO itself remains
// un-opened). It then adds the FifoFd to the given exec.Cmd as an inherited
// fd, with _LIBCONTAINER_FIFOFD set to its fd number.
func (c *linuxContainer) includeExecFifo(cmd *exec.Cmd) error {
	fifoName := filepath.Join(c.root, execFifoFilename)
	fifo, err := os.OpenFile(fifoName, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	c.fifo = fifo

	cmd.ExtraFiles = append(cmd.ExtraFiles, fifo)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_FIFOFD="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1))
	return nil
}

func (c *linuxContainer) newParentProcess(p *Process) (parentProcess, error) {
	parentInitPipe, childInitPipe, err := utils.NewSockPair("init")
	if err != nil {
		return nil, fmt.Errorf("unable to create init pipe: %w", err)
	}
	messageSockPair := filePair{parentInitPipe, childInitPipe}

	parentLogPipe, childLogPipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("unable to create log pipe: %w", err)
	}
	logFilePair := filePair{parentLogPipe, childLogPipe}

	cmd := c.commandTemplate(p, childInitPipe, childLogPipe)
	if !p.Init {
		return c.newSetnsProcess(p, cmd, messageSockPair, logFilePair)
	}

	// We only set up fifoFd if we're not doing a `runc exec`. The historic
	// reason for this is that previously we would pass a dirfd that allowed
	// for container rootfs escape (and not doing it in `runc exec` avoided
	// that problem), but we no longer do that. However, there's no need to do
	// this for `runc exec` so we just keep it this way to be safe.
	if err := c.includeExecFifo(cmd); err != nil {
		return nil, fmt.Errorf("unable to setup exec fifo: %w", err)
	}
	return c.newInitProcess(p, cmd, messageSockPair, logFilePair)
}

func (c *linuxContainer) commandTemplate(p *Process, childInitPipe *os.File, childLogPipe *os.File) *exec.Cmd {
	cmd := exec.Command(c.initPath, c.initArgs[1:]...)
	cmd.Args[0] = c.initArgs[0]
	cmd.Stdin = p.Stdin
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &unix.SysProcAttr{}
	}
	cmd.Env = append(cmd.Env, "GOMAXPROCS="+os.Getenv("GOMAXPROCS"))
	cmd.ExtraFiles = append(cmd.ExtraFiles, p.ExtraFiles...)
	if p.ConsoleSocket != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, p.ConsoleSocket)
		cmd.Env = append(cmd.Env,
			"_LIBCONTAINER_CONSOLE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, childInitPipe)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_INITPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		"_LIBCONTAINER_STATEDIR="+c.root,
	)

	cmd.ExtraFiles = append(cmd.ExtraFiles, childLogPipe)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_LOGPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		"_LIBCONTAINER_LOGLEVEL="+p.LogLevel,
	)

	// NOTE: when running a container with no PID namespace and the parent process spawning the container is
	// PID1 the pdeathsig is being delivered to the container's init process by the kernel for some reason
	// even with the parent still running.
	if c.config.ParentDeathSignal > 0 {
		cmd.SysProcAttr.Pdeathsig = unix.Signal(c.config.ParentDeathSignal)
	}
	return cmd
}

// shouldSendMountSources says whether the child process must setup bind mounts with
// the source pre-opened (O_PATH) in the host user namespace.
// See https://github.com/opencontainers/runc/issues/2484
func (c *linuxContainer) shouldSendMountSources() bool {
	// Passing the mount sources via SCM_RIGHTS is only necessary when
	// both userns and mntns are active.
	if !c.config.Namespaces.Contains(configs.NEWUSER) ||
		!c.config.Namespaces.Contains(configs.NEWNS) {
		return false
	}

	// nsexec.c send_mountsources() requires setns(mntns) capabilities
	// CAP_SYS_CHROOT and CAP_SYS_ADMIN.
	if c.config.RootlessEUID {
		return false
	}

	// We need to send sources if there are bind-mounts.
	for _, m := range c.config.Mounts {
		if m.IsBind() {
			return true
		}
	}

	return false
}

func (c *linuxContainer) newInitProcess(p *Process, cmd *exec.Cmd, messageSockPair, logFilePair filePair) (*initProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
	nsMaps := make(map[configs.NamespaceType]string)
	for _, ns := range c.config.Namespaces {
		if ns.Path != "" {
			nsMaps[ns.Type] = ns.Path
		}
	}
	_, sharePidns := nsMaps[configs.NEWPID]
	data, err := c.bootstrapData(c.config.Namespaces.CloneFlags(), nsMaps, initStandard)
	if err != nil {
		return nil, err
	}

	if c.shouldSendMountSources() {
		// Elements on this slice will be paired with mounts (see StartInitialization() and
		// prepareRootfs()). This slice MUST have the same size as c.config.Mounts.
		mountFds := make([]int, len(c.config.Mounts))
		for i, m := range c.config.Mounts {
			if !m.IsBind() {
				// Non bind-mounts do not use an fd.
				mountFds[i] = -1
				continue
			}

			// The fd passed here will not be used: nsexec.c will overwrite it with dup3(). We just need
			// to allocate a fd so that we know the number to pass in the environment variable. The fd
			// must not be closed before cmd.Start(), so we reuse messageSockPair.child because the
			// lifecycle of that fd is already taken care of.
			cmd.ExtraFiles = append(cmd.ExtraFiles, messageSockPair.child)
			mountFds[i] = stdioFdCount + len(cmd.ExtraFiles) - 1
		}

		mountFdsJson, err := json.Marshal(mountFds)
		if err != nil {
			return nil, fmt.Errorf("Error creating _LIBCONTAINER_MOUNT_FDS: %w", err)
		}

		cmd.Env = append(cmd.Env,
			"_LIBCONTAINER_MOUNT_FDS="+string(mountFdsJson),
		)
	}

	init := &initProcess{
		cmd:             cmd,
		messageSockPair: messageSockPair,
		logFilePair:     logFilePair,
		manager:         c.cgroupManager,
		intelRdtManager: c.intelRdtManager,
		config:          c.newInitConfig(p),
		container:       c,
		process:         p,
		bootstrapData:   data,
		sharePidns:      sharePidns,
	}
	c.initProcess = init
	return init, nil
}

func (c *linuxContainer) newSetnsProcess(p *Process, cmd *exec.Cmd, messageSockPair, logFilePair filePair) (*setnsProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initSetns))
	state, err := c.currentState()
	if err != nil {
		return nil, fmt.Errorf("unable to get container state: %w", err)
	}
	// for setns process, we don't have to set cloneflags as the process namespaces
	// will only be set via setns syscall
	data, err := c.bootstrapData(0, state.NamespacePaths, initSetns)
	if err != nil {
		return nil, err
	}
	proc := &setnsProcess{
		cmd:             cmd,
		cgroupPaths:     state.CgroupPaths,
		rootlessCgroups: c.config.RootlessCgroups,
		intelRdtPath:    state.IntelRdtPath,
		messageSockPair: messageSockPair,
		logFilePair:     logFilePair,
		manager:         c.cgroupManager,
		config:          c.newInitConfig(p),
		process:         p,
		bootstrapData:   data,
		initProcessPid:  state.InitProcessPid,
	}
	if len(p.SubCgroupPaths) > 0 {
		if add, ok := p.SubCgroupPaths[""]; ok {
			// cgroup v1: using the same path for all controllers.
			// cgroup v2: the only possible way.
			for k := range proc.cgroupPaths {
				subPath := path.Join(proc.cgroupPaths[k], add)
				if !strings.HasPrefix(subPath, proc.cgroupPaths[k]) {
					return nil, fmt.Errorf("%s is not a sub cgroup path", add)
				}
				proc.cgroupPaths[k] = subPath
			}
			// cgroup v2: do not try to join init process's cgroup
			// as a fallback (see (*setnsProcess).start).
			proc.initProcessPid = 0
		} else {
			// Per-controller paths.
			for ctrl, add := range p.SubCgroupPaths {
				if val, ok := proc.cgroupPaths[ctrl]; ok {
					subPath := path.Join(val, add)
					if !strings.HasPrefix(subPath, val) {
						return nil, fmt.Errorf("%s is not a sub cgroup path", add)
					}
					proc.cgroupPaths[ctrl] = subPath
				} else {
					return nil, fmt.Errorf("unknown controller %s in SubCgroupPaths", ctrl)
				}
			}
		}
	}
	return proc, nil
}

func (c *linuxContainer) newInitConfig(process *Process) *initConfig {
	cfg := &initConfig{
		Config:           c.config,
		Args:             process.Args,
		Env:              process.Env,
		User:             process.User,
		AdditionalGroups: process.AdditionalGroups,
		Cwd:              process.Cwd,
		Capabilities:     process.Capabilities,
		PassedFilesCount: len(process.ExtraFiles),
		ContainerId:      c.ID(),
		NoNewPrivileges:  c.config.NoNewPrivileges,
		RootlessEUID:     c.config.RootlessEUID,
		RootlessCgroups:  c.config.RootlessCgroups,
		AppArmorProfile:  c.config.AppArmorProfile,
		ProcessLabel:     c.config.ProcessLabel,
		Rlimits:          c.config.Rlimits,
		CreateConsole:    process.ConsoleSocket != nil,
		ConsoleWidth:     process.ConsoleWidth,
		ConsoleHeight:    process.ConsoleHeight,
	}
	if process.NoNewPrivileges != nil {
		cfg.NoNewPrivileges = *process.NoNewPrivileges
	}
	if process.AppArmorProfile != "" {
		cfg.AppArmorProfile = process.AppArmorProfile
	}
	if process.Label != "" {
		cfg.ProcessLabel = process.Label
	}
	if len(process.Rlimits) > 0 {
		cfg.Rlimits = process.Rlimits
	}
	if cgroups.IsCgroup2UnifiedMode() {
		cfg.Cgroup2Path = c.cgroupManager.Path("")
	}

	return cfg
}

func (c *linuxContainer) Destroy() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.state.destroy()
}

func (c *linuxContainer) Pause() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	switch status {
	case Running, Created:
		if err := c.cgroupManager.Freeze(configs.Frozen); err != nil {
			return err
		}
		return c.state.transition(&pausedState{
			c: c,
		})
	}
	return ErrNotRunning
}

func (c *linuxContainer) Resume() error {
	c.m.Lock()
	defer c.m.Unlock()
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	if status != Paused {
		return ErrNotPaused
	}
	if err := c.cgroupManager.Freeze(configs.Thawed); err != nil {
		return err
	}
	return c.state.transition(&runningState{
		c: c,
	})
}

func (c *linuxContainer) NotifyOOM() (<-chan struct{}, error) {
	// XXX(cyphar): This requires cgroups.
	if c.config.RootlessCgroups {
		logrus.Warn("getting OOM notifications may fail if you don't have the full access to cgroups")
	}
	path := c.cgroupManager.Path("memory")
	if cgroups.IsCgroup2UnifiedMode() {
		return notifyOnOOMV2(path)
	}
	return notifyOnOOM(path)
}

func (c *linuxContainer) NotifyMemoryPressure(level PressureLevel) (<-chan struct{}, error) {
	// XXX(cyphar): This requires cgroups.
	if c.config.RootlessCgroups {
		logrus.Warn("getting memory pressure notifications may fail if you don't have the full access to cgroups")
	}
	return notifyMemoryPressure(c.cgroupManager.Path("memory"), level)
}

func (c *linuxContainer) updateState(process parentProcess) (*State, error) {
	if process != nil {
		c.initProcess = process
	}
	state, err := c.currentState()
	if err != nil {
		return nil, err
	}
	err = c.saveState(state)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (c *linuxContainer) saveState(s *State) (retErr error) {
	tmpFile, err := os.CreateTemp(c.root, "state-")
	if err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	err = utils.WriteJSON(tmpFile, s)
	if err != nil {
		return err
	}
	err = tmpFile.Close()
	if err != nil {
		return err
	}

	stateFilePath := filepath.Join(c.root, stateFilename)
	return os.Rename(tmpFile.Name(), stateFilePath)
}

func (c *linuxContainer) currentStatus() (Status, error) {
	if err := c.refreshState(); err != nil {
		return -1, err
	}
	return c.state.status(), nil
}

// refreshState needs to be called to verify that the current state on the
// container is what is true.  Because consumers of libcontainer can use it
// out of process we need to verify the container's status based on runtime
// information and not rely on our in process info.
func (c *linuxContainer) refreshState() error {
	paused, err := c.isPaused()
	if err != nil {
		return err
	}
	if paused {
		return c.state.transition(&pausedState{c: c})
	}
	t := c.runType()
	switch t {
	case Created:
		return c.state.transition(&createdState{c: c})
	case Running:
		return c.state.transition(&runningState{c: c})
	}
	return c.state.transition(&stoppedState{c: c})
}

func (c *linuxContainer) runType() Status {
	if c.initProcess == nil {
		return Stopped
	}
	pid := c.initProcess.pid()
	stat, err := system.Stat(pid)
	if err != nil {
		return Stopped
	}
	if stat.StartTime != c.initProcessStartTime || stat.State == system.Zombie || stat.State == system.Dead {
		return Stopped
	}
	// We'll create exec fifo and blocking on it after container is created,
	// and delete it after start container.
	if _, err := os.Stat(filepath.Join(c.root, execFifoFilename)); err == nil {
		return Created
	}
	return Running
}

func (c *linuxContainer) isPaused() (bool, error) {
	state, err := c.cgroupManager.GetFreezerState()
	if err != nil {
		return false, err
	}
	return state == configs.Frozen, nil
}

func (c *linuxContainer) currentState() (*State, error) {
	var (
		startTime           uint64
		externalDescriptors []string
		pid                 = -1
	)
	if c.initProcess != nil {
		pid = c.initProcess.pid()
		startTime, _ = c.initProcess.startTime()
		externalDescriptors = c.initProcess.externalDescriptors()
	}

	intelRdtPath := ""
	if c.intelRdtManager != nil {
		intelRdtPath = c.intelRdtManager.GetPath()
	}
	state := &State{
		BaseState: BaseState{
			ID:                   c.ID(),
			Config:               *c.config,
			InitProcessPid:       pid,
			InitProcessStartTime: startTime,
			Created:              c.created,
		},
		Rootless:            c.config.RootlessEUID && c.config.RootlessCgroups,
		CgroupPaths:         c.cgroupManager.GetPaths(),
		IntelRdtPath:        intelRdtPath,
		NamespacePaths:      make(map[configs.NamespaceType]string),
		ExternalDescriptors: externalDescriptors,
	}
	if pid > 0 {
		for _, ns := range c.config.Namespaces {
			state.NamespacePaths[ns.Type] = ns.GetPath(pid)
		}
		for _, nsType := range configs.NamespaceTypes() {
			if !configs.IsNamespaceSupported(nsType) {
				continue
			}
			if _, ok := state.NamespacePaths[nsType]; !ok {
				ns := configs.Namespace{Type: nsType}
				state.NamespacePaths[ns.Type] = ns.GetPath(pid)
			}
		}
	}
	return state, nil
}

func (c *linuxContainer) currentOCIState() (*specs.State, error) {
	bundle, annotations := utils.Annotations(c.config.Labels)
	state := &specs.State{
		Version:     specs.Version,
		ID:          c.ID(),
		Bundle:      bundle,
		Annotations: annotations,
	}
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	state.Status = specs.ContainerState(status.String())
	if status != Stopped {
		if c.initProcess != nil {
			state.Pid = c.initProcess.pid()
		}
	}
	return state, nil
}

// orderNamespacePaths sorts namespace paths into a list of paths that we
// can setns in order.
func (c *linuxContainer) orderNamespacePaths(namespaces map[configs.NamespaceType]string) ([]string, error) {
	paths := []string{}
	for _, ns := range configs.NamespaceTypes() {

		// Remove namespaces that we don't need to join.
		if !c.config.Namespaces.Contains(ns) {
			continue
		}

		if p, ok := namespaces[ns]; ok && p != "" {
			// check if the requested namespace is supported
			if !configs.IsNamespaceSupported(ns) {
				return nil, fmt.Errorf("namespace %s is not supported", ns)
			}
			// only set to join this namespace if it exists
			if _, err := os.Lstat(p); err != nil {
				return nil, fmt.Errorf("namespace path: %w", err)
			}
			// do not allow namespace path with comma as we use it to separate
			// the namespace paths
			if strings.ContainsRune(p, ',') {
				return nil, fmt.Errorf("invalid namespace path %s", p)
			}
			paths = append(paths, fmt.Sprintf("%s:%s", configs.NsName(ns), p))
		}

	}

	return paths, nil
}

func encodeIDMapping(idMap []configs.IDMap) ([]byte, error) {
	data := bytes.NewBuffer(nil)
	for _, im := range idMap {
		line := fmt.Sprintf("%d %d %d\n", im.ContainerID, im.HostID, im.Size)
		if _, err := data.WriteString(line); err != nil {
			return nil, err
		}
	}
	return data.Bytes(), nil
}

func (c *linuxContainer) Checkpoint(criuOpts *CriuOpts) error {
	return fmt.Errorf("Checkpointing is not supported in this release")
}

// netlinkError is an error wrapper type for use by custom netlink message
// types. Panics with errors are wrapped in netlinkError so that the recover
// in bootstrapData can distinguish intentional panics.
type netlinkError struct{ error }
