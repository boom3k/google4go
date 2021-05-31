package google4go

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/boom3k/utils4go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log"
	"os"
)

// Generate Used to generate authorized Oauth2 tokens
func Generate(oauth2ConfigFile []byte, scopes []string) (*oauth2.Token, error) {
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

// WriteToFile Used to save oauth2 token files
func WriteToFile(token oauth2.Token, newFileName string, encryptFile bool) (oauth2.Token, []byte, error) {
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

// ParseFromFile Used to parse token file data into a oauth2 token
func ParseFromFile(tokenFileData []byte) (*oauth2.Token, error) {
	token := &oauth2.Token{}
	err := json.Unmarshal(tokenFileData, token)
	return token, err
}