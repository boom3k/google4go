package google4go

import (
	"context"
	"encoding/json"
	"github.com/boom3k/utils4go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"log"
	"net/http"
	"os"
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

// InitializeOauth2Client Used for Oauth2 authorized clients
func InitializeOauth2Client(clientSecretFile []byte, token *oauth2.Token, scopes []string) (*http.Client, error) {
	oauth2, err := google.ConfigFromJSON(clientSecretFile, scopes...)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	Oauth2HttpClient = oauth2.Client(context.Background(), token)
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
	ServiceAccountHttpClient = jwt.Client(context.Background())
	return jwt.Client(context.Background()), nil
}

// ServiceInitiatorFromNestedFunction Used with a passed function to return service initiation parameters
func ServiceInitiatorFromNestedFunction(initClient func() *http.Client) (context.Context, option.ClientOption) {
	ctx := context.Background()
	opt := option.WithHTTPClient(initClient())
	return ctx, opt
}

// NewOauth2HTTPInitializer Used to pass directly into a *.NewService() function
func NewOauth2HTTPInitializer(clientSecretFile []byte, token *oauth2.Token, scopes []string) (context.Context, option.ClientOption) {
	InitializeOauth2Client(clientSecretFile, token, scopes)
	return Oauth2ApiInitializer()
}

// NewServiceAccountHTTPInitializer NewServiceAccountHTTPInitializer Used to pass directly into a *.NewService() function
func NewServiceAccountHTTPInitializer(subject string, serviceAccountFile []byte, scopes []string) (context.Context, option.ClientOption) {
	InitializeServiceAccountClient(subject, serviceAccountFile, scopes)
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
