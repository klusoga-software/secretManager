package secretManager

import (
	"context"
	"errors"
	vault "github.com/hashicorp/vault/api"
	approleAuth "github.com/hashicorp/vault/api/auth/approle"
	kubernetesAuth "github.com/hashicorp/vault/api/auth/kubernetes"
	"log"
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))

type SecretManager interface {
	VaultClient() *vault.Client
	LoginWithAppRole(approleId string, approleSecret string) error
	LoginWithToken(token string)
	LoginWithKubernetes(role string, opts ...kubernetesAuth.LoginOption) error
}

type secretManager struct {
	client *vault.Client
}

func (s *secretManager) VaultClient() *vault.Client {
	return s.client
}

func NewSecretManager(url string) (SecretManager, error) {
	config := vault.DefaultConfig()

	config.Address = url

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &secretManager{client: client}, nil
}

func (s *secretManager) LoginWithAppRole(approleId string, approleSecret string) error {
	as := approleAuth.SecretID{FromString: approleSecret}

	approleAuth, err := approleAuth.NewAppRoleAuth(approleId, &as)
	if err != nil {
		return err
	}

	authInfo, err := s.client.Auth().Login(context.TODO(), approleAuth)
	if err != nil {
		return err
	}

	go func() {
		err = ManageSecretLifetime(s.client, authInfo, true)
		if err != nil {
			log.Fatal(err.Error())
			return
		}
	}()

	return nil
}

func (s *secretManager) LoginWithToken(token string) {
	s.client.SetToken(token)
}

func (s *secretManager) LoginWithKubernetes(role string, opts ...kubernetesAuth.LoginOption) error {
	k8sAuth, err := kubernetesAuth.NewKubernetesAuth(role, opts...)
	if err != nil {
		return err
	}

	authSecret, err := s.client.Auth().Login(context.TODO(), k8sAuth)
	if err != nil {
		return err
	}

	go func() {
		err = ManageSecretLifetime(s.client, authSecret, true)
		if err != nil {
			log.Fatal(err.Error())
			return
		}
	}()

	return nil
}

func ManageSecretLifetime(client *vault.Client, secret *vault.Secret, isAuthToken bool) error {
	if isAuthToken {
		if !secret.Auth.Renewable {
			return errors.New("secret is not renewable")
		}
	} else {
		if !secret.Renewable {
			return errors.New("secret is not renewable")
		}
	}

	watcher, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:    secret,
		Increment: 3600,
	})
	if err != nil {
		return err
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				return err
			}
			return nil

		case renewal := <-watcher.RenewCh():
			logger.Info("Token was renewed", "renewedAt", renewal.RenewedAt)
		}
	}
}
