package protocols

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"sync"
)

// SSH function provides a menu for managing SSH and Fail2Ban services
func SSH() {
	for {
		fmt.Print("\n1. Setup SSH and Fail2Ban services.")
		fmt.Print("\n2. Stop SSH and Fail2Ban services.")
		fmt.Print("\n3. Show ban list.")
		fmt.Print("\n4. Unban IP.")
		fmt.Print("\n0. Exit\n")
		fmt.Print("\nOpenSSH >> ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			startServices()
		case 2:
			stopServices()
		case 3:
			showbannedIps()
		case 4:
			unbanIp()
		case 0:
			fmt.Println("Bye!")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Global variables for synchronization
var (
    cleanupWG sync.WaitGroup
    sshRunning bool
)

// startServices starts SSH and Fail2Ban services
func startServices() {
    startService("ssh")
    jailConf()
    startService("fail2ban")

    // Create a temp file to indicate that SSH is running
    createTempFile("/var/run/ssh_running")
    sshRunning = true

    // Start a goroutine to handle signals
    cleanupWG.Add(1)
    go signalHandler()
}

// stopServices stops SSH and Fail2Ban services
func stopServices() {
    if sshRunning {
        // Clean up by removing the file
        removeTempFile("/var/run/ssh_running")
        sshRunning = false
    }

    // Stop services (for example, graceful shutdown)
    stopService("ssh")
    stopService("fail2ban")

    // Signal completion of cleanup
    cleanupWG.Done()
}

// signalHandler handles SIGINT and SIGTERM signals
func signalHandler() {
    defer cleanupWG.Done()

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    // Stop services and clean up
    stopServices()
}

// createTempFile creates a temporary file
func createTempFile(filePath string) {
    file, err := os.Create(filePath)
    if err != nil {
        panic(err)
    }
    defer file.Close()
    fmt.Printf("Created temporary file %s\n", filePath)
}

// removeTempFile removes a temporary file
func removeTempFile(filePath string) {
    err := os.Remove(filePath)
    if err != nil {
        fmt.Printf("Error removing file %s: %v\n", filePath, err)
    } else {
        fmt.Printf("Removed temporary file %s\n", filePath)
    }
}

func showbannedIps() {

	fmt.Println("\nBanned IPs --> ")

	// Show the status of Fail2Ban including banned IPs
	err := runCommand("fail2ban-client", "status")
	if err != nil {
		fmt.Printf("\nFailed to show banned IPs, error: %s\n", err)
		return
	}

}

// unbanIp unbans a specific IP address
func unbanIp() {
	
	// Read the IP address to unban
	var unban string
	fmt.Printf("\nUnban IP: ")
	fmt.Scanln(&unban)

	// Specify the jail name, adjust as necessary
	jail := "sshd"

	// Execute the command to unban the IP
	err := runCommand("fail2ban-client", "set", jail, "unbanip", unban)
	if err != nil {
		fmt.Printf("\nFailed to unban IP: %s\n", unban)
	} else {
		fmt.Println("\nIP removed from jail.")
	}
}

// jailConf creates a jail.local configuration file if it doesn't exist
func jailConf() {
	// Define the configuration content
	configContent := `
[DEFAULT]
# Ban the IP for 10 minutes:
bantime = 600

# Check logs every minute:
findtime = 600

# Ban an IP after 5 failed attempts:
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
backend = systemd
`

	// Path to the configuration file
	filePath := "/etc/fail2ban/jail.local"

	// Check if the file exists
	if fileExists(filePath) {
		fmt.Println("Jail file already exists. No changes made.")
		return
	}

	// Write the configuration to the file
	err := writeConfigFile(filePath, configContent)
	if err != nil {
		fmt.Printf("Failed to create jail file: %v\n", err)
		return
	}

	fmt.Println("Jail file created successfully.")
}

// fileExists checks if a file exists and is not a directory
func fileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return !info.IsDir()
}

// writeConfigFile writes the given content to the specified file
func writeConfigFile(filePath, content string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("unable to create or open file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return fmt.Errorf("unable to write to file: %v", err)
	}

	return nil
}

// runCommand executes a command and returns any error encountered
func runCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}
