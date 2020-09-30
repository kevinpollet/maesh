package identity

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/traefik/mesh/v2/cmd"
	"github.com/traefik/mesh/v2/pkg/identity"
	"github.com/traefik/mesh/v2/pkg/k8s"
	"github.com/traefik/paerser/cli"
)

// NewCmd builds a new identity command.
func NewCmd(config *cmd.IdentityConfiguration, loaders []cli.ResourceLoader) *cli.Command {
	identityCmd := &cli.Command{
		Name:          "identity",
		Description:   `Starts the identity provider.`,
		Configuration: config,
		Run: func(_ []string) error {
			return identityCommand(config)
		},
		Resources: loaders,
	}

	identityAgentConfig := cmd.NewIdentityAgentConfiguration()
	if err := identityCmd.AddCommand(NewAgentCmd(identityAgentConfig, loaders)); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	return identityCmd
}

func identityCommand(config *cmd.IdentityConfiguration) error {
	ctx := cmd.ContextWithSignal(context.Background())

	logger, err := cmd.NewLogger(config.LogFormat, config.LogLevel, false)
	if err != nil {
		return fmt.Errorf("could not create logger: %w", err)
	}

	logger.Debug("Starting identity provider...")
	logger.Debugf("Using masterURL: %q", config.MasterURL)
	logger.Debugf("Using kubeconfig: %q", config.KubeConfig)

	clients, err := k8s.NewClient(logger, config.MasterURL, config.KubeConfig)
	if err != nil {
		return fmt.Errorf("error building clients: %w", err)
	}

	ca, err := identity.NewCertificationAuthority(config.TrustDomain)
	if err != nil {
		return err
	}

	attestor := identity.NewProxyAttestor(config.Namespace, config.ProxyServiceAccountName, clients.KubernetesClient())

	dnsName := fmt.Sprintf("%s.%s.svc.%s", config.ServiceName, config.Namespace, config.ClusterDomain)

	idp, err := identity.NewProvider(attestor, ca, logger, config.Host, config.Port, dnsName)
	if err != nil {
		return fmt.Errorf("unable to create the identity provider API: %w", err)
	}

	errCh := make(chan error)

	go func() {
		if err := idp.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("identity provider has stopped unexpectedly: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err

	case <-ctx.Done():
		if err := stopIdentityProvider(idp); err != nil {
			return err
		}
	}

	return nil
}

func stopIdentityProvider(idp *identity.Provider) error {
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := idp.Shutdown(stopCtx); err != nil {
		return fmt.Errorf("unable to stop identity provider: %w", err)
	}

	return nil
}
