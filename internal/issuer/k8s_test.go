package issuer

import (
	"context"
	"errors"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestKubernetesVerifier_VerifyTokenReview(t *testing.T) {
	const (
		token      = "sa-token"
		audience   = "herald"
		subject    = "system:serviceaccount:build:runner"
		wrongToken = "wrong token"
	)

	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		create := action.(ktesting.CreateAction)
		tr := create.GetObject().(*authnv1.TokenReview)
		if tr.Spec.Token != token {
			return true, &authnv1.TokenReview{Status: authnv1.TokenReviewStatus{Authenticated: false}}, nil
		}
		if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != audience {
			t.Fatalf("TokenReview audiences = %v, want [%s]", tr.Spec.Audiences, audience)
		}
		return true, &authnv1.TokenReview{
			ObjectMeta: metav1.ObjectMeta{Name: "review"},
			Status: authnv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{audience},
				User:          authnv1.UserInfo{Username: subject},
			},
		}, nil
	})

	got, err := NewKubernetesVerifier(client, audience).Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != subject {
		t.Fatalf("subject = %q, want %q", got, subject)
	}

	_, err = NewKubernetesVerifier(client, audience).Verify(context.Background(), wrongToken)
	if err == nil {
		t.Fatal("Verify accepted token review without expected token")
	}
}

func TestKubernetesVerifier_RejectsUnauthenticatedOrWrongAudience(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status authnv1.TokenReviewStatus
	}{
		{name: "unauthenticated", status: authnv1.TokenReviewStatus{Authenticated: false}},
		{name: "wrong audience", status: authnv1.TokenReviewStatus{
			Authenticated: true,
			Audiences:     []string{"other"},
			User:          authnv1.UserInfo{Username: "system:serviceaccount:build:runner"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			client.Fake.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
				return true, &authnv1.TokenReview{Status: tc.status}, nil
			})

			_, err := NewKubernetesVerifier(client, "herald").Verify(context.Background(), "token")
			if err == nil {
				t.Fatal("Verify succeeded; want error")
			}
		})
	}
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()
	want := staticVerifier("subject")
	reg.Register("issuer-id", want)

	got, ok := reg.Verifier("issuer-id")
	if !ok {
		t.Fatal("Verifier not found")
	}
	sub, err := got.Verify(context.Background(), "attestation")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sub != "subject" {
		t.Fatalf("subject = %q, want subject", sub)
	}

	if _, ok := reg.Verifier("missing"); ok {
		t.Fatal("missing verifier found")
	}
}

type staticVerifier string

func (s staticVerifier) Verify(context.Context, string) (string, error) {
	if s == "" {
		return "", errors.New("no subject")
	}
	return string(s), nil
}
