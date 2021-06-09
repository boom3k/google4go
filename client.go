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

var globalClient = &http.Client{}

// InitializeOauth2Client Used for Oauth2 authorized clients
func InitializeOauth2Client(clientSecretFile []byte, token *oauth2.Token, scopes []string) (*http.Client, error) {
	oauth2, err := google.ConfigFromJSON(clientSecretFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	globalClient = oauth2.Client(context.Background(), token)
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
	globalClient = jwt.Client(context.Background())
	return jwt.Client(context.Background()), nil
}

// ServiceInitiatorFromNestedFunction Used with a passed function to return service initiation parameters
func ServiceInitiatorFromNestedFunction(initClient func() *http.Client) (context.Context, option.ClientOption) {
	ctx := context.Background()
	opt := option.WithHTTPClient(initClient())
	return ctx, opt
}

// ServiceInitializer Used with a pre initiated client to return service initiation parameters
func ServiceInitializer() (context.Context, option.ClientOption) {
	if globalClient == nil {
		log.Fatalln("Client not initiated..")
		return nil, nil
	}
	ctx := context.Background()
	opt := option.WithHTTPClient(globalClient)
	return ctx, opt
}

// GenerateToken Used to generate authorized Oauth2 tokens
func GenerateToken(oauth2ConfigFile []byte, scopes []string) (*oauth2.Token, error) {
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

// WriteToken Used to save oauth2 token files
func WriteToken(token oauth2.Token, newFileName string, encryptFile bool) (oauth2.Token, []byte, error) {
	tokenJson, err := json.Marshal(token)
	if err != nil {
		log.Println(err.Error())
		return token, nil, nil
	}

	if encryptFile {
		tempFileName := "temp.bat"
		err := os.WriteFile(tempFileName, tokenJson, os.ModePerm)
		if err != nil {
			log.Println(err.Error())
			return token, nil, nil
		}

		_, err = utils4go.EncryptFile(tempFileName, utils4go.GeneratePassword(), true)
		if err != nil {
			log.Println(err.Error())
			return token, nil, nil
		}
		return token, tokenJson, err
	}
	return token, tokenJson, os.WriteFile(newFileName, tokenJson, os.ModePerm)
}

// ParseToken Used to parse token file data into a oauth2 token
func ParseToken(tokenFileData []byte) (*oauth2.Token, error) {
	token := &oauth2.Token{}
	err := json.Unmarshal(tokenFileData, token)
	return token, err
}

// ParseTokenFromPath Used to pase token from file path
func ParseTokenFromPath(filepath string) (*oauth2.Token, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ParseToken(data)

}
