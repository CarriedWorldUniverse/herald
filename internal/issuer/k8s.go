package issuer

import (
	"context"
	"errors"
	"fmt"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesVerifier struct {
	client      kubernetes.Interface
	expectedAud string
}

func NewKubernetesVerifier(client kubernetes.Interface, expectedAud string) *KubernetesVerifier {
	return &KubernetesVerifier{client: client, expectedAud: expectedAud}
}

func (v *KubernetesVerifier) Verify(ctx context.Context, attestation string) (string, error) {
	if attestation == "" {
		return "", errors.New("empty attestation")
	}
	tr, err := v.client.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     attestation,
			Audiences: []string{v.expectedAud},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("tokenreview create: %w", err)
	}
	if !tr.Status.Authenticated {
		return "", errors.New("tokenreview unauthenticated")
	}
	if !hasAudience(tr.Status.Audiences, v.expectedAud) {
		return "", errors.New("tokenreview audience mismatch")
	}
	if tr.Status.User.Username == "" {
		return "", errors.New("tokenreview missing username")
	}
	return tr.Status.User.Username, nil
}

func hasAudience(got []string, want string) bool {
	for _, aud := range got {
		if aud == want {
			return true
		}
	}
	return false
}
