package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	vault "github.com/hashicorp/vault/api"
	authAWS "github.com/hashicorp/vault/api/auth/aws"
	authK8s "github.com/hashicorp/vault/api/auth/kubernetes"
)

// REQURED VALUES
// VAULT_AUTH_ROLE // VAULT_AUTH_PATH eks-prod // VAULT_SECRET_PATH

// ---Kubernetes:
// KUBERNETES_ROLE
// AWS_SHARED_CREDENTIALS_FILE
//
// ---AWS IAM:
// AWS_ROLE
// AWS_SHARED_CREDENTIALS_FILE

func main() {
	// initialising Vault client
	client, err := vault.NewClient(
		&vault.Config{
			Address: "https://vault-address",
		},
	)
	if err != nil {
		log.Fatal(fmt.Errorf("unable to initialize Vault client: %w", err))
	}

	var AuthSecret *vault.Secret

	// login
	loginMethod, err := getVaultLoginMethod()
	if err != nil {
		log.Fatal(fmt.Errorf("LOGIN: %w", err))
	}
	switch loginMethod {
	case "kubernetes":
		if AuthSecret, err = loginKubernetes(client); err != nil {
			log.Fatal(fmt.Errorf("%w", err))
		}
	case "iam":
		if AuthSecret, err = loginIAM(client); err != nil {
			log.Fatal(fmt.Errorf("%w", err))
		}
	default:
		log.Fatal(fmt.Errorf("Incorrect login method: %w", err))
	}

	// token renewal process
	if AuthSecret.Renewable {
		watcher, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
			Secret: AuthSecret,
		})
		if err != nil {
			log.Fatal("error initializing vault lifetime watcher")
		}
		log.Printf("Successfully started vault token renewal watcher")
		go StartTokenWatcher(watcher)
	}

	// get secret
	secret, err := client.Logical().Read("secret/path")
	if err != nil {
		log.Fatal(fmt.Errorf("unable to read secret: %w", err))
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		log.Fatal(fmt.Errorf("data type assertion failed: %T %#v", secret.Data["data"], secret.Data["data"]))
	}
	key := "SECRET_KEY" // key that we want to get from vault
	value, ok := data[key].(string)
	if !ok {
		log.Fatal(fmt.Errorf("value type assertion failed: %T %#v", data[key], data[key]))
	}
	log.Print(value)
}

func loginIAM(client *vault.Client) (*vault.Secret, error) {
	// Fetches a key-value secret (kv-v2) after authenticating to Vault via AWS IAM,
	// one of two auth methods used to authenticate with AWS (the other is EC2 auth).
	//
	// If role not provided, Vault will fall back on looking for a role with the IAM role name if you're using the iam auth type,
	// or the EC2 instance's AMI id if using the ec2 auth type
	awsAuth, err := authAWS.NewAWSAuth(
		authAWS.WithRole("role-name"),
		authAWS.WithRegion("us-west-2"),
	)
	if err != nil {
		return nil, fmt.Errorf("aws iam auth: %w", err)
	}
	authInfo, err := client.Auth().Login(context.TODO(), awsAuth)
	if err != nil {
		return authInfo, fmt.Errorf("aws iam login: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after AWS IAM login")
	}

	return authInfo, nil
}
func loginKubernetes(client *vault.Client) (*vault.Secret, error) {
	// The service-account token will be read from the path where the token's
	// Kubernetes Secret is mounted. By default, Kubernetes will mount it to
	// /var/run/secrets/kubernetes.io/serviceaccount/token, but an administrator
	// may have configured it to be mounted elsewhere.
	// In that case, we'll use the option WithServiceAccountTokenPath to look
	// for the token there.
	k8sAuth, err := authK8s.NewKubernetesAuth(
		"role-name", // role
		authK8s.WithMountPath("mount-path"),
	)
	if err != nil {
		return nil, fmt.Errorf("kubernetes auth: %w", err)
	}
	secret, err := client.Auth().Login(context.TODO(), k8sAuth)
	if err != nil {
		return secret, fmt.Errorf("kubernetes login: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no auth info was returned after Kubernetes login")
	}

	return secret, nil
}

func getVaultLoginMethod() (string, error) {
	// check if Kubernetes Secret mounted
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return "kubernetes", nil
	}

	// if not - trying to locate AWS shared credential
	sess, err := session.NewSession()
	if err != nil {
		return "", fmt.Errorf("unable to start AWS session: %w", err)
	}
	credentials, err := sess.Config.Credentials.Get()
	if err != nil {
		return "", fmt.Errorf("unable to get AWS credentials: %w", err)
	}
	// setting up env (required by Vault module)
	os.Setenv("AWS_ACCESS_KEY_ID", credentials.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", credentials.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", credentials.SessionToken)
	return "iam", nil
}

func StartTokenWatcher(watcher *vault.LifetimeWatcher) {
	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				log.Fatal(err)
			}
			// Renewal is now over
		case renewal := <-watcher.RenewCh():
			log.Printf("Successfully renewed vault token: %#v", renewal)
		}
	}
}
