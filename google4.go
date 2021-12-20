package google4go

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/boom3k/utils4go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var AdminScopes = []string{
	"https://www.googleapis.com/auth/admin.reports.audit.readonly",
	"https://www.googleapis.com/auth/admin.reports.usage.readonly",
	"https://www.googleapis.com/auth/apps.groups.settings",
	"https://www.googleapis.com/auth/androidmanagement",
	"https://www.googleapis.com/auth/apps.groups.migration",
	"https://www.googleapis.com/auth/apps.groups.settings",
	"https://www.googleapis.com/auth/admin.datatransfer",
	"https://www.googleapis.com/auth/cloudplatformprojects",
	"https://www.googleapis.com/auth/cloud_search",
	"https://www.googleapis.com/auth/apps.licensing",
	"https://www.googleapis.com/auth/admin.chrome.printers",
	"https://www.googleapis.com/auth/admin.chrome.printers.readonly",
	"https://www.googleapis.com/auth/admin.directory.customer",
	"https://www.googleapis.com/auth/admin.directory.customer.readonly",
	"https://www.googleapis.com/auth/admin.directory.device.chromeos",
	"https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
	"https://www.googleapis.com/auth/admin.directory.device.mobile",
	"https://www.googleapis.com/auth/admin.directory.device.mobile.action",
	"https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
	"https://www.googleapis.com/auth/admin.directory.domain",
	"https://www.googleapis.com/auth/admin.directory.domain.readonly",
	"https://www.googleapis.com/auth/admin.directory.group",
	"https://www.googleapis.com/auth/admin.directory.group.member",
	"https://www.googleapis.com/auth/admin.directory.group.member.readonly",
	"https://www.googleapis.com/auth/admin.directory.group.readonly",
	"https://www.googleapis.com/auth/admin.directory.orgunit",
	"https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
	"https://www.googleapis.com/auth/admin.directory.resource.calendar",
	"https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly",
	"https://www.googleapis.com/auth/admin.directory.rolemanagement",
	"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
	"https://www.googleapis.com/auth/admin.directory.user",
	"https://www.googleapis.com/auth/admin.directory.user.alias",
	"https://www.googleapis.com/auth/admin.directory.user.alias.readonly",
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.user.security",
	"https://www.googleapis.com/auth/admin.directory.userschema",
	"https://www.googleapis.com/auth/admin.directory.userschema.readonly",
	"https://www.googleapis.com/auth/cloud-platform",
}

var ServiceAccountScopes = []string{
	"https://mail.google.com/",
	"https://sites.google.com/feeds",
	"https://www.google.com/m8/feeds",
	"https://www.googleapis.com/auth/drive",
	"https://www.googleapis.com/auth/activity",
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/contacts",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/gmail.settings.basic",
	"https://www.googleapis.com/auth/gmail.settings.sharing",
}

var Oauth2HttpClient = &http.Client{}
var ServiceAccountHttpClient = &http.Client{}

// GetOauth2HttpClient Used for Oauth2 authorized clients
func GetOauth2HttpClient(clientSecretFile []byte, token *oauth2.Token, scopes []string) (*http.Client, error) {
	oauth2, err := google.ConfigFromJSON(clientSecretFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	Oauth2HttpClient = oauth2.Client(context.Background(), token)
	return oauth2.Client(context.Background(), token), nil
}

// GetOauth2HttpClientUsingFilepath Used for Oauth2 authorized clients using file paths
func GetOauth2HttpClientUsingFilepath(clientSecretFilePath, tokenPath string, scopes []string) (*http.Client, error) {
	clientSecretStream, err := ioutil.ReadFile(clientSecretFilePath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}

	tokenStream, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	return GetOauthHttp2ClientUsingStream(clientSecretStream, tokenStream, scopes)
}

// GetOauthHttp2ClientUsingStream Used for Oauth2 authorized clients with only files and scopes
func GetOauthHttp2ClientUsingStream(clientSecretFile, token []byte, scopes []string) (*http.Client, error) {
	oauth2, err := google.ConfigFromJSON(clientSecretFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	oauth2Token, err := ParseToken(token)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	Oauth2HttpClient = oauth2.Client(context.Background(), oauth2Token)
	return oauth2.Client(context.Background(), oauth2Token), nil
}

// GetServiceAccountHttpClient Used for service accounts with domain wide delegation
func GetServiceAccountHttpClient(subject string, serviceAccountFile []byte, scopes []string) (*http.Client, error) {
	jwt, err := google.JWTConfigFromJSON(serviceAccountFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	jwt.Subject = subject
	ServiceAccountHttpClient = jwt.Client(context.Background())
	log.Printf("Acting as %v via --> [%s]", jwt.Subject, jwt.Email)
	return jwt.Client(context.Background()), nil
}

// GetServiceAccountHttpClientUsingFilePath Used for service accounts with domain wide delegation witha path to the service account key file
func GetServiceAccountHttpClientUsingFilePath(subject, serviceAccountFilePath string, scopes []string) (*http.Client, error) {
	serviceAccountFile, err := ioutil.ReadFile(serviceAccountFilePath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	jwt, err := google.JWTConfigFromJSON(serviceAccountFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	jwt.Subject = subject
	ServiceAccountHttpClient = jwt.Client(context.Background())
	log.Printf("Acting as %v via --> [%s]", jwt.Subject, jwt.Email)
	return jwt.Client(context.Background()), nil
}

// ServiceInitiatorFromNestedFunction Used with a passed function to return service initiation parameters
func ServiceInitiatorFromNestedFunction(initClient func() *http.Client) (context.Context, option.ClientOption) {
	ctx := context.Background()
	opt := option.WithHTTPClient(initClient())
	return ctx, opt
}

// NewOauth2HttpInitializer Used to pass directly into a *.NewService() function
func NewOauth2HttpInitializer(clientSecretFile []byte, token *oauth2.Token, scopes []string) (context.Context, option.ClientOption) {
	GetOauth2HttpClient(clientSecretFile, token, scopes)
	return Oauth2ApiInitializer()
}

// NewServiceAccountHttpInitializer Used to pass directly into a *.NewService() function
func NewServiceAccountHttpInitializer(subject string, serviceAccountFile []byte, scopes []string) (context.Context, option.ClientOption) {
	GetServiceAccountHttpClient(subject, serviceAccountFile, scopes)
	return ServiceAccountApiInitializer()
}

// Oauth2ApiInitializer Used with a pre initiated oauth2 client to return service initiation parameters
func Oauth2ApiInitializer() (context.Context, option.ClientOption) {
	if Oauth2HttpClient == nil {
		log.Fatalln("Client not initiated..")
		return nil, nil
	}
	ctx := context.Background()
	opt := option.WithHTTPClient(Oauth2HttpClient)
	return ctx, opt
}

// ServiceAccountApiInitializer Used with a pre initiated oauth2 client to return service initiation parameters
func ServiceAccountApiInitializer() (context.Context, option.ClientOption) {
	if Oauth2HttpClient == nil {
		log.Fatalln("Client not initiated..")
		return nil, nil
	}
	ctx := context.Background()
	opt := option.WithHTTPClient(ServiceAccountHttpClient)
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
	log.Println("Go to the following link in your browser then type the authorization code:", authenticationURL)
	code := utils4go.Readline("Enter the code:")
	token, err := oauth2Config.Exchange(context.TODO(), code)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	return token, nil
}

// GenerateAndWriteToken Used to generate authorized Oauth2 tokens and write them to a file
func GenerateAndWriteToken(oauth2ConfigFile []byte, scopes []string, encrypt bool) ([]byte, error) {
	token, err := GenerateToken(oauth2ConfigFile, scopes)
	if err != nil {
		return nil, err
	}
	return WriteToken(*token, "token.json", encrypt)
}

// WriteToken Used to save oauth2 token files
func WriteToken(token oauth2.Token, newFileName string, encryptFile bool) ([]byte, error) {
	tokenJson, err := json.Marshal(token)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	if encryptFile {
		tempFileName := "temp.bat"
		err := os.WriteFile(tempFileName, tokenJson, os.ModePerm)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}

		_, err = utils4go.EncryptFile(tempFileName, utils4go.GeneratePassword(), true)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}
		return tokenJson, os.Rename(tempFileName, newFileName)
	}

	return tokenJson, os.WriteFile(newFileName, tokenJson, os.ModePerm)
}

// ParseToken Used to parse token file data into a oauth2 token
func ParseToken(tokenFileData []byte) (*oauth2.Token, error) {
	token := &oauth2.Token{}
	err := json.Unmarshal(tokenFileData, token)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	return token, err
}

// ParseTokenFromPath Used to pase token from file path
func ParseTokenFromPath(filepath string) (*oauth2.Token, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	return ParseToken(data)

}

type UserInfo struct {
	ID            string
	Email         string
	VerifiedEmail bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	Locale        string
	Hd            string
	Token         *oauth2.Token
}

func GetUserInfo(accessToken string) *UserInfo {
	url := "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=" + accessToken
	httpClient := &http.Client{}
	response, err := httpClient.Get(url)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	defer response.Body.Close()
	m := make(map[string]interface{})
	json.NewDecoder(response.Body).Decode(&m)
	log.Println("User info retrieved from <" + url + ">")
	userInfo := &UserInfo{}
	for key, value := range m {
		switch key {
		case "id":
			userInfo.ID = value.(string)
		case "email":
			userInfo.Email = value.(string)
		case "name":
			userInfo.Email = value.(string)
		case "given_name":
			userInfo.Email = value.(string)
		case "picture":
			userInfo.Email = value.(string)
		case "locale":
			userInfo.Email = value.(string)
		case "hd":
			userInfo.Email = value.(string)
		case "family_name":
			userInfo.FamilyName = value.(string)
		case "verified_email":
			userInfo.VerifiedEmail = value.(bool)
		}
	}
	return userInfo
}
