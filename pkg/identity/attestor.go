package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ProxyAttestor struct {
	namespace          string
	serviceAccountName string
	kubeClient         kubernetes.Interface
}

func NewProxyAttestor(namespace, serviceAccountName string, kubeClient kubernetes.Interface) *ProxyAttestor {
	return &ProxyAttestor{
		namespace:          namespace,
		serviceAccountName: serviceAccountName,
		kubeClient:         kubeClient,
	}
}

func (pa *ProxyAttestor) Attest(ctx context.Context, token string) error {
	namespace, serviceAccountName, err := pa.validateToken(ctx, token)
	if err != nil {
		return err
	}

	if namespace != pa.namespace || serviceAccountName != pa.serviceAccountName {
		return fmt.Errorf("\"%s:%s\" is not is not a proxy service account", namespace, serviceAccountName)
	}

	return nil
}

func (pa *ProxyAttestor) validateToken(ctx context.Context, token string) (string, string, error) {
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	tokenReview, err := pa.kubeClient.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		return "", "", fmt.Errorf("unable to create token review: %w", err)
	}

	if tokenReview.Status.Error != "" {
		return "", "", fmt.Errorf("unable to check token: %s", tokenReview.Status.Error)
	}

	if !tokenReview.Status.Authenticated {
		return "", "", errors.New("token is associated with an unknown user")
	}

	// Service accounts authenticate with the username system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)
	parts := strings.Split(tokenReview.Status.User.Username, ":")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("unable to parse username: %s", tokenReview.Status.User.Username)
	}

	return parts[2], parts[3], nil
}
