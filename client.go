package google4go

import (
	"context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"log"
	"net/http"
)

var client = &http.Client{}

// InitializeOauth2Client Used for Oauth2 authorized clients
func InitializeOauth2Client(clientSecretFile []byte, token *oauth2.Token, scopes []string) (*http.Client, error) {
	oauth2, err := google.ConfigFromJSON(clientSecretFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	client = oauth2.Client(context.Background(), token)
	return oauth2.Client(context.Background(), token), nil
}

// InitializeServiceAccountClient Used for service accounts with domain wide delegation
func InitializeServiceAccountClient(subject string, serviceAccountFile []byte, scopes []string) (*http.Client, error) {
	jwt, err := google.JWTConfigFromJSON(serviceAccountFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	jwt.Subject = subject
	client = jwt.Client(context.Background())
	return jwt.Client(context.Background()), nil
}

// ServiceInitiatorFromNestedFunction Used with a passed function to return service initiation parameters
func ServiceInitiatorFromNestedFunction(initClient func() *http.Client) (context.Context, option.ClientOption) {
	ctx := context.Background()
	opt := option.WithHTTPClient(initClient())
	return ctx, opt
}

// ServiceInitiator Used with a pre initiated client to return service initiation parameters
func ServiceInitiator() (context.Context, option.ClientOption) {
	if client == nil {
		log.Fatalln("Client not initiated..")
		return nil, nil
	}
	ctx := context.Background()
	opt := option.WithHTTPClient(client)
	return ctx, opt
}
