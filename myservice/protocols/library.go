package protocols

import (
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func closePorts(name string) {
	cmd := exec.Command("ufw", "deny", name)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to close port %s: %v\n", name, err)
	} else {
		fmt.Printf("Port %s closed successfully.\n", name)
	}
}

func openPorts(name string) {
	cmd := exec.Command("ufw", "allow", name)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to allow port %s: %v\n", name, err)
	} else {
		fmt.Printf("Port %s allowed successfully.\n", name)
	}
}

func checkService(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", serviceName)
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}


func startService(serviceName string) {
	if !checkService(serviceName) {
		cmd := exec.Command("systemctl", "start", serviceName)
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Failed to start service %s: %v\n", serviceName, err)
		} else if !checkService(serviceName){
			fmt.Printf("Service %s started with error.\n", serviceName)
		} else {
			fmt.Printf("Service %s started successfully.\n", serviceName)
		}
	}
}

func stopService(serviceName string) {
	cmd := exec.Command("systemctl", "stop", serviceName)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to stop service %s: %v\n", serviceName, err)
	} else {
		fmt.Printf("Service %s stopped successfully.\n", serviceName)
	}
}

func SetUpService(service string) {
	if !checkService(service) {
		startService(service)
	} else {
		fmt.Printf("Service %s already up and running.\n", service)
		fmt.Println("Restarting service...")
		cmd := exec.Command("systemctl", "restart", service)
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Could not restart service: %s\n", err)
			return
		} else {
			fmt.Println("Service restart successful.")
		}
	}
}

func terminalReadPassword() ([]byte, error) {
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Move to the next line after password input
	return password, err
}
