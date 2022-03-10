package google4go

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type ApiConfiguration struct {
	ClientId              string   `json:"client_id"`
	ClientSecret          string   `json:"client_secret"`
	Oauth2ConfigPath      string   `json:"oauth_2_config_path"`
	Oauth2TokenPath       string   `json:"oauth_2_token_path"`
	Oauth2UserEmail       string   `json:"oauth_2_user_email"`
	Oauth2Scopes          []string `json:"oauth_2_scopes"`
	AccessToken           string   `json:"access_token"`
	RefreshToken          string   `json:"refresh_token"`
	ServiceAccountKeyPath string   `json:"service_account_key_path"`
	ServiceAccountScopes  []string `json:"service_account_scopes"`
}

func GenerateConfigFile() {
	config := &ApiConfiguration{}
	data, err := json.Marshal(config)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	err = ioutil.WriteFile("google_api_config.json", data, os.ModePerm)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
}

func ReadConfigFile(configFile []byte) *ApiConfiguration {
	apiConfig := &ApiConfiguration{}
	err := json.Unmarshal(configFile, &apiConfig)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	return apiConfig
}

func (receiver *ApiConfiguration) GetServiceAccountClient(subject string) *http.Client {
	keyData, err := ioutil.ReadFile(receiver.ServiceAccountKeyPath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}

	client, err := GetServiceAccountHttpClient(subject, keyData, receiver.ServiceAccountScopes)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}

	return client
}

func (receiver *ApiConfiguration) GetOauth2Client() *http.Client {
	clientSecretData, err := ioutil.ReadFile(receiver.Oauth2ConfigPath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}

	oauth2TokenData, err := ioutil.ReadFile(receiver.Oauth2TokenPath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}

	client, err := GetOauthHttp2ClientUsingStream(clientSecretData, oauth2TokenData, receiver.Oauth2Scopes)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}

	return client
}
