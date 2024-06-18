package main

import (
	"fmt"
	"os/exec"
)

// installServices installs the necessary services
func main() {
	services := []string{"ssh", "lftp", "ftp", "openssl", "fail2ban", "ufw", "sqlite3 libsqlite3-dev"}

	for _, service := range services {
		err := installService(service)
		if err != nil {
			fmt.Printf("Failed to install %s, error: %s\n", service, err)
		} else {
			fmt.Printf("%s installed successfully.\n", service)
		}
	}
}

// installService installs a single service using apt-get
func installService(service string) error {
	cmd := exec.Command("apt-get", "install", "-y", service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}
