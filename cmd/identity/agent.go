package identity

import (
	"context"
	"fmt"

	"github.com/traefik/mesh/v2/cmd"
	"github.com/traefik/mesh/v2/pkg/identity"
	"github.com/traefik/paerser/cli"
)

// NewAgentCmd builds a new identity client command.
func NewAgentCmd(config *cmd.IdentityAgentConfiguration, loaders []cli.ResourceLoader) *cli.Command {
	return &cli.Command{
		Name:          "agent",
		Description:   `Starts the identity agent.`,
		Configuration: config,
		Run: func(_ []string) error {
			return identityAgentCommand(config)
		},
		Resources: loaders,
	}
}

func identityAgentCommand(config *cmd.IdentityAgentConfiguration) error {
	ctx := cmd.ContextWithSignal(context.Background())

	logger, err := cmd.NewLogger(config.LogFormat, config.LogLevel, false)
	if err != nil {
		return fmt.Errorf("could not create logger: %w", err)
	}

	logger.Debug("Starting identity provider client...")

	agent := identity.NewAgent(
		logger,
		config.TrustDomain,
		config.Namespace,
		config.ServiceAccountName,
		config.IssuerURL,
	)

	errCh := make(chan error)

	go func() {
		if err := agent.Run(); err != nil {
			errCh <- fmt.Errorf("identity agent has stopped unexpectedly: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err

	case <-ctx.Done():
		agent.Shutdown()
	}

	return nil
}
