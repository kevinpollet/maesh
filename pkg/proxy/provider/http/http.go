package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/job"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/provider"
	"github.com/containous/traefik/v2/pkg/safe"
	"github.com/containous/traefik/v2/pkg/tls"
)

var _ provider.Provider = (*Provider)(nil)

// providerName is the name of the provider for logging.
const providerName = "http"

// Provider is a provider.Provider implementation that queries an endpoint for a configuration.
type Provider struct {
	Endpoint       string        `description:"Load configuration from this endpoint." json:"endpoint" toml:"endpoint" yaml:"endpoint" export:"true"`
	PollInterval   time.Duration `description:"Polling interval for endpoint." json:"pollInterval,omitempty" toml:"pollInterval,omitempty" yaml:"pollInterval,omitempty"`
	PollTimeout    time.Duration `description:"Polling timeout for endpoint." json:"pollTimeout,omitempty" toml:"pollTimeout,omitempty" yaml:"pollTimeout,omitempty"`
	httpClient     *http.Client
	previous       dynamic.Message
	previousData   string
	previousConfig *dynamic.Configuration
}

// New creates a new instance of the HTTP provider.
func New(endpoint string, pollInterval time.Duration, pollTimeout time.Duration) *Provider {
	return &Provider{
		Endpoint:     endpoint,
		PollInterval: pollInterval,
		PollTimeout:  pollTimeout,
	}
}

// Init the provider.
func (p *Provider) Init() error {
	if p.Endpoint == "" {
		return fmt.Errorf("a non-empty endpoint is required")
	}

	if p.PollInterval == 0 {
		p.PollInterval = 1 * time.Second
	}

	if p.PollTimeout == 0 {
		p.PollTimeout = 1 * time.Second
	}

	p.httpClient = &http.Client{Timeout: p.PollTimeout}

	return nil
}

// Provide allows the provider to provide configurations to traefik
// using the given configuration channel.
// nolint:gocognit // This requires a refactor that will come in its own PR.
func (p *Provider) Provide(configurationChan chan<- dynamic.Message, pool *safe.Pool) error {
	pool.GoCtx(func(routineCtx context.Context) {
		ctxLog := log.With(routineCtx, log.Str(log.ProviderName, providerName))
		logger := log.FromContext(ctxLog)

		operation := func() error {
			ticker := time.NewTicker(p.PollInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					/*data, err := p.getDataFromEndpoint(ctxLog)
					if err != nil {
						logger.Errorf("Failed to get config from endpoint: %v", err)
						return err
					}*/

					configuration := &dynamic.Configuration{
						HTTP: &dynamic.HTTPConfiguration{
							Routers:     make(map[string]*dynamic.Router),
							Middlewares: make(map[string]*dynamic.Middleware),
							Services:    make(map[string]*dynamic.Service),
						},
						TCP: &dynamic.TCPConfiguration{
							Routers:  make(map[string]*dynamic.TCPRouter),
							Services: make(map[string]*dynamic.TCPService),
						},
						TLS: &dynamic.TLSConfiguration{
							Stores:  make(map[string]tls.Store),
							Options: make(map[string]tls.Options),
						},
						UDP: &dynamic.UDPConfiguration{
							Routers:  make(map[string]*dynamic.UDPRouter),
							Services: make(map[string]*dynamic.UDPService),
						},
					}

					data := "{\"http\":{\"routers\":{\"default-whoami-http-80\":{\"entryPoints\":[\"http-5000\"],\"service\":\"default-whoami-http-80\",\"rule\":\"Host(`whoami-http.default.maesh`) || Host(`10.99.239.249`)\",\"priority\":1001},\"readiness\":{\"entryPoints\":[\"readiness\"],\"service\":\"readiness\",\"rule\":\"Path(`/ping`)\"}},\"services\":{\"block-all-service\":{\"loadBalancer\":{\"passHostHeader\":null}},\"default-whoami-http-80\":{\"loadBalancer\":{\"servers\":[{\"url\":\"http://10.244.1.7:80\"},{\"url\":\"http://10.244.1.8:80\"},{\"url\":\"http://10.244.2.7:80\"}],\"passHostHeader\":true}},\"readiness\":{\"loadBalancer\":{\"servers\":[{\"url\":\"http://127.0.0.1:8080\"}],\"passHostHeader\":true}}},\"middlewares\":{\"block-all-middleware\":{\"ipWhiteList\":{\"sourceRange\":[\"255.255.255.255\"]}}}},\"tcp\":{\"routers\":{\"default-whoami-tcp-8080\":{\"entryPoints\":[\"tcp-10000\"],\"service\":\"default-whoami-tcp-8080\",\"rule\":\"HostSNI(`*`)\"}},\"services\":{\"default-whoami-tcp-8080\":{\"loadBalancer\":{\"servers\":[{\"address\":\"10.244.1.10:8080\"},{\"address\":\"10.244.1.9:8080\"},{\"address\":\"10.244.2.8:8080\"}]}}}},\"udp\":{}}"

					if err := json.Unmarshal([]byte(data), configuration); err != nil {
						logger.Errorf("Error parsing configuration: %v", err)
						return err
					}

					message := dynamic.Message{
						ProviderName:  providerName,
						Configuration: configuration,
					}

					// configuration.HTTP = nil
					//if p.previousConfig != nil {
					//	fmt.Println(reflect.DeepEqual(configuration.TCP, p.previousConfig.TCP))
					//}

					// configuration.UDP = nil
					// configuration.TLS = nil


					// configuration.TCP = nil

					fmt.Println("---------")
					fmt.Println("Config DeepEqual", reflect.DeepEqual(p.previousConfig, configuration))
					fmt.Println("Message DeepEqual", reflect.DeepEqual(p.previous, message))

					p.previous = message
					p.previousConfig = configuration
					p.previousData = string(data)

					fmt.Println("Message Sent")
					configurationChan <- message

				case <-routineCtx.Done():
					return nil
				}
			}
		}

		notify := func(err error, time time.Duration) {
			logger.Errorf("Provider connection error, retrying in %s: %v", time, err)
		}
		err := backoff.RetryNotify(safe.OperationWithRecover(operation), backoff.WithContext(job.NewBackOff(backoff.NewExponentialBackOff()), ctxLog), notify)
		if err != nil {
			logger.Errorf("Cannot connect to HTTP server: %v", err)
		}
	})

	return nil
}

// getDataFromEndpoint returns data from the configured provider endpoint.
func (p *Provider) getDataFromEndpoint(ctx context.Context) ([]byte, error) {
	resp, err := p.httpClient.Get(p.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to get data from endpoint %q: %w", p.Endpoint, err)
	}

	if resp == nil {
		return nil, fmt.Errorf("received no data from endpoint")
	}

	defer resp.Body.Close()

	var data []byte

	if data, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-ok response code: %d", resp.StatusCode)
	}

	log.FromContext(ctx).Debugf("Successfully received data from endpoint: %q", p.Endpoint)

	return data, nil
}
