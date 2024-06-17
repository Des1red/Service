package main

import (
	
	"fmt"
	"os"
	"myclient/connectclient"
)

func main() {
	if !CheckArguments() {
		return
	}
	service := os.Args[1]
	server := os.Args[2]
	checkservice := options(service)
	if !checkservice {
		showservices()
		return
	} else {
		connecttoservice(service, server)
	}
}

func connecttoservice(service, server string) {
	if service == "ftps" {
		connectclient.Ftpsclient(server)
	}

	if service == "sftp" {
		connectclient.Sftpclient(server)
	}
}

func options(service string) bool {
	switch service {
	case "ftps":
		return true
	case "sftp":
		return true
	default:
		fmt.Println("Unknown Service")
		return false
	}
}

func showservices() {
	fmt.Println("ftps sftp ssh")
}

func CheckArguments() bool {
	Usagemsg := "Usage: go run client.go <service> <server>.\n"
	if len(os.Args) < 2 {
		fmt.Print("Missing Service.\n")
		fmt.Print(Usagemsg)
		return false
	} else if len(os.Args) < 3 {
		fmt.Print("Missing Server.\n")
		fmt.Print(Usagemsg)
		return false
	} else if len(os.Args) > 3 {
		fmt.Print("Too many arguments.")
		fmt.Print(Usagemsg)
		return false
	} else {
		return true
	}
}
