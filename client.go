package google4go

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/boom3k/utils4go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"log"
	"net/http"
	"os"
)

var client = &http.Client{}

// InitOauth2Client Used for Oauth2 authorized clients
func InitOauth2Client(clientSecretFile []byte, token *oauth2.Token, scopes []string) (*http.Client, error) {
	oauth2, err := google.ConfigFromJSON(clientSecretFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	client = oauth2.Client(context.Background(), token)
	return oauth2.Client(context.Background(), token), nil
}

// InitServiceAccountClient Used for service accounts with domain wide delegation
func InitServiceAccountClient(subject string, serviceAccountFile []byte, scopes []string) (*http.Client, error) {
	jwt, err := google.JWTConfigFromJSON(serviceAccountFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	jwt.Subject = subject
	client = jwt.Client(context.Background())
	return jwt.Client(context.Background()), nil
}

// GenerateOauth2Tokens Used to generate authorized Oauth2 tokens
func GenerateOauth2Tokens(oauth2ConfigFile []byte, scopes []string) (*oauth2.Token, error) {
	oauth2Config, err := google.ConfigFromJSON(oauth2ConfigFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	authenticationURL := oauth2Config.AuthCodeURL("state-oauth2Token", oauth2.ApprovalForce)
	fmt.Println("Go to the following link in your browser then type the authorization code:", authenticationURL)
	code := utils4go.Readline("Enter the code:")
	token, err := oauth2Config.Exchange(context.TODO(), code)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	return token, nil
}

// SaveTokensFile Used to save oauth2 token files
func SaveTokensFile(token oauth2.Token, newFileName string, encryptFile bool) error {
	tokenJson, err := json.Marshal(token)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	if encryptFile {
		tempFileName := "temp.bat"
		err := os.WriteFile(tempFileName, tokenJson, os.ModePerm)
		if err != nil {
			log.Println(err.Error())
			return err
		}
		_, err = utils4go.EncryptFile(tempFileName, utils4go.GeneratePassword(), true)
		if err != nil {
			return err
		}
		return os.Rename(tempFileName, newFileName)
	}
	return os.WriteFile(newFileName, tokenJson, os.ModePerm)
}

// ParseOauth2Token Used to parse token file data into a oauth2 token
func ParseOauth2Token(tokenFileData []byte) (*oauth2.Token, error) {
	token := &oauth2.Token{}
	err := json.Unmarshal(tokenFileData, token)
	return token, err
}

// GetServiceInitiatorFromNestedFunction Used with a passed function to return service initiation parameters
func GetServiceInitiatorFromNestedFunction(initClient func() *http.Client) (context.Context, option.ClientOption) {
	ctx := context.Background()
	opt := option.WithHTTPClient(initClient())
	return ctx, opt
}

// GetServiceInitiator Used with a pre initiated client to return service initiation parameters
func GetServiceInitiator() (context.Context, option.ClientOption) {
	if client == nil {
		log.Fatalln("Client not initiated..")
		return nil, nil
	}
	ctx := context.Background()
	opt := option.WithHTTPClient(client)
	return ctx, opt
}
