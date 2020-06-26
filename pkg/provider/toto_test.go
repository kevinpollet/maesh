package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/job"
	"github.com/containous/traefik/v2/pkg/safe"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {

	var previousConfig *dynamic.Configuration
	var previous dynamic.Message

	operation := func() error {
		ticker := time.NewTicker(2 * time.Second)

		for {
			select {
			case <-ticker.C:
				/*data, err := p.getDataFromEndpoint(ctxLog)
				if err != nil {
					logger.Errorf("Failed to get config from endpoint: %v", err)
					return err
				}*/

				configuration := &dynamic.Configuration{}

				data := "{\"http\":{\"routers\":{\"default-whoami-http-80\":{\"entryPoints\":[\"http-5000\"],\"service\":\"default-whoami-http-80\",\"rule\":\"Host(`whoami-http.default.maesh`) || Host(`10.99.239.249`)\",\"priority\":1001},\"readiness\":{\"entryPoints\":[\"readiness\"],\"service\":\"readiness\",\"rule\":\"Path(`/ping`)\"}},\"services\":{\"block-all-service\":{\"loadBalancer\":{\"passHostHeader\":null}},\"default-whoami-http-80\":{\"loadBalancer\":{\"servers\":[{\"url\":\"http://10.244.1.7:80\"},{\"url\":\"http://10.244.1.8:80\"},{\"url\":\"http://10.244.2.7:80\"}],\"passHostHeader\":true}},\"readiness\":{\"loadBalancer\":{\"servers\":[{\"url\":\"http://127.0.0.1:8080\"}],\"passHostHeader\":true}}},\"middlewares\":{\"block-all-middleware\":{\"ipWhiteList\":{\"sourceRange\":[\"255.255.255.255\"]}}}},\"tcp\":{\"routers\":{\"default-whoami-tcp-8080\":{\"entryPoints\":[\"tcp-10000\"],\"service\":\"default-whoami-tcp-8080\",\"rule\":\"HostSNI(`*`)\"}},\"services\":{\"default-whoami-tcp-8080\":{\"loadBalancer\":{\"servers\":[{\"address\":\"10.244.1.10:8080\"},{\"address\":\"10.244.1.9:8080\"},{\"address\":\"10.244.2.8:8080\"}]}}}},\"udp\":{}}"

				if err := json.Unmarshal([]byte(data), configuration); err != nil {
					require.NoError(t, err)
				}

				message := dynamic.Message{
					ProviderName:  "http",
					Configuration: configuration,
				}

				// configuration.HTTP = nil
				// if p.previousConfig != nil {
				//	fmt.Println(reflect.DeepEqual(configuration.TCP, p.previousConfig.TCP))
				// }

				// configuration.UDP = nil
				// configuration.TLS = nil

				// configuration.TCP = nil

				fmt.Println("---------")
				fmt.Println("Config DeepEqual", reflect.DeepEqual(previousConfig, configuration))
				fmt.Println("Message DeepEqual", reflect.DeepEqual(previous, message))

				previous = message
				previousConfig = configuration

				fmt.Println("Message Sent")
			}
		}
	}

	notify := func(err error, time time.Duration) {
		require.NoError(t, err)
	}
	err := backoff.RetryNotify(safe.OperationWithRecover(operation), backoff.WithContext(job.NewBackOff(backoff.NewExponentialBackOff()), context.Background()), notify)
	if err != nil {
		require.NoError(t, err)
	}
}
