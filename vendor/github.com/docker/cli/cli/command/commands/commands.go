package commands

import (
	"os"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/container"
	"github.com/docker/cli/cli/command/image"
	"github.com/docker/cli/cli/command/manifest"
	"github.com/docker/cli/cli/command/network"
	"github.com/docker/cli/cli/command/registry"
	"github.com/docker/cli/cli/command/system"
	"github.com/docker/cli/cli/command/volume"
	"github.com/spf13/cobra"
)

// AddCommands adds all the commands from cli/command to the root command
func AddCommands(cmd *cobra.Command, dockerCli command.Cli) {
	cmd.AddCommand(
		// container
		container.NewContainerCommand(dockerCli),
		container.NewRunCommand(dockerCli),

		// image
		image.NewImageCommand(dockerCli),

		// manifest
		manifest.NewManifestCommand(dockerCli),

		// network
		network.NewNetworkCommand(dockerCli),

		// registry
		registry.NewLoginCommand(dockerCli),
		registry.NewLogoutCommand(dockerCli),
		registry.NewSearchCommand(dockerCli),

		// system
		system.NewSystemCommand(dockerCli),
		system.NewVersionCommand(dockerCli),

		// volume
		volume.NewVolumeCommand(dockerCli),

		// legacy commands may be hidden
		hide(system.NewInspectCommand(dockerCli)),
		hide(container.NewAttachCommand(dockerCli)),
		hide(container.NewExecCommand(dockerCli)),
		hide(container.NewKillCommand(dockerCli)),
		hide(container.NewLogsCommand(dockerCli)),
		hide(container.NewPsCommand(dockerCli)),
		hide(container.NewRestartCommand(dockerCli)),
		hide(container.NewRmCommand(dockerCli)),
		hide(container.NewStartCommand(dockerCli)),
		hide(container.NewStopCommand(dockerCli)),
		hide(container.NewWaitCommand(dockerCli)),
		hide(image.NewImagesCommand(dockerCli)),
		hide(image.NewPullCommand(dockerCli)),
		hide(image.NewRemoveCommand(dockerCli)),
		hide(image.NewTagCommand(dockerCli)),
	)
}

func hide(cmd *cobra.Command) *cobra.Command {
	// If the environment variable with name "DOCKER_HIDE_LEGACY_COMMANDS" is not empty,
	// these legacy commands (such as `docker ps`, `docker exec`, etc)
	// will not be shown in output console.
	if os.Getenv("DOCKER_HIDE_LEGACY_COMMANDS") == "" {
		return cmd
	}
	cmdCopy := *cmd
	cmdCopy.Hidden = true
	cmdCopy.Aliases = []string{}
	return &cmdCopy
}
