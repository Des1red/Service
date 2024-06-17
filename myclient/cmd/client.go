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
    var sshkey string
    if len(os.Args) == 4 {
        sshkey = os.Args[3]
    }

    if !isValidService(service) {
        showServices()
        return
    }

    connectToService(service, server, sshkey)
}

func connectToService(service, server, sshkey string) {
    switch service {
    case "ftps":
        connectclient.Ftpsclient(server)
    case "sftp":
        connectclient.Sftpclient(server, sshkey)
    default:
        fmt.Println("Unsupported service")
    }
}

func isValidService(service string) bool {
    switch service {
    case "ftps", "sftp":
        return true
    default:
        fmt.Println("Unknown Service")
        return false
    }
}

func showServices() {
    fmt.Println("Available services: ftps, sftp")
}

func CheckArguments() bool {
    usageMsg := "Usage: go run client.go <service> <server> [<private ssh key>]\n"

    if len(os.Args) < 2 {
        fmt.Print("Missing Service.\n")
        fmt.Print(usageMsg)
        return false
    }

    service := os.Args[1]

    if len(os.Args) < 3 {
        fmt.Print("Missing Server.\n")
        fmt.Print(usageMsg)
        return false
    }

    if service == "sftp" {
        if len(os.Args) != 4 {
            fmt.Print("Missing or too many arguments for sftp service.\n")
            fmt.Print(usageMsg)
            return false
        }
    } else {
        if len(os.Args) > 3 {
            fmt.Print("Too many arguments.\n")
            fmt.Print(usageMsg)
            return false
        }
    }

    return true
}
