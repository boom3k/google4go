package google4go

import (
	"context"
	_ "embed"
	"fmt"
	"google.golang.org/api/drive/v2"
	"google.golang.org/api/option"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestReadConfigFile(t *testing.T) {
	file, err := ioutil.ReadFile("google_api_config.json")
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	config := ReadConfigFile(file)
	fmt.Println(config)
}

func TestGenerateConfigFile(t *testing.T) {
	GenerateConfigFile()
}

func TestConfig(t *testing.T) {
	file, err := ioutil.ReadFile("test/google_api_config.json")
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	config := ReadConfigFile(file)
	config.ServiceAccountScopes = append(config.ServiceAccountScopes, drive.DriveScope)
	driveService, err := drive.NewService(context.Background(), option.WithHTTPClient(config.GetServiceAccountClient(os.Args[5])))
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	response, err := driveService.About.Get().Fields("*").Do()
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	log.Println(response.PermissionId)
}
