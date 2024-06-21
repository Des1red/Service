package protocols

import (
	"fmt"
	"os/exec"
	"syscall"
	"os"
	"golang.org/x/crypto/ssh/terminal"
)

// close given port
func closePorts(name string) {
	cmd := exec.Command("ufw", "deny", name)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to close port %s: %v\n", name, err)
	} else {
		fmt.Printf("Port %s closed successfully.\n", name)
	}
}

// open given port
func openPorts(name string) {
	cmd := exec.Command("ufw", "allow", name)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to allow port %s: %v\n", name, err)
	} else {
		fmt.Printf("Port %s allowed successfully.\n", name)
	}
}

// check if service is active
func checkService(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", serviceName)
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

// start service
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

// stop service
func stopService(serviceName string) {
	cmd := exec.Command("systemctl", "stop", serviceName)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to stop service %s: %v\n", serviceName, err)
	} else {
		fmt.Printf("Service %s stopped successfully.\n", serviceName)
	}
}

//check service restart if its running 
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

// Function to check if a directory exists
func directoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// make sure MySystem Dir exists to save certificates and server settings
func ensureMySystem() {
	systemSettingsPath := "/MySystem/settings"
	// create directory to store certificates
	if !directoryExists(systemSettingsPath) {
		// Create the directory along with any necessary parents
			err := os.MkdirAll(systemSettingsPath, os.ModePerm)
			if err != nil {
				fmt.Println("Error creating directory:", err)
				return
			}
	
			fmt.Println("Directory created successfully:", systemSettingsPath)
		} else {
			fmt.Print("Found System Dir, continue ...")
		}	
	
}
