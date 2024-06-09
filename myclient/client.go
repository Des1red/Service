package main

import (
	
	"fmt"
	"os"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"bufio"
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
		ftpsclientconnect(server)
	}
}

// getCertificate fetches the server certificate and writes it to a PEM file.
func getCertificate(server string) string {
	// Create the openssl command with arguments
	cmd := exec.Command("openssl", "s_client", "-connect", server+":21", "-starttls", "ftp")

	// Create a pipe to capture the command's output
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating pipe:", err)
		return ""
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting command:", err)
		return ""
	}

	// Read the output and write the certificate to a file
	name := "server_cert_" + server + ".pem"
	file, err := os.Create(name)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return ""
	}
	defer file.Close()

	// Use io.TeeReader to simultaneously capture the output while writing to file
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, outPipe)
		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()

	// Use bufio.Scanner to process the output and extract the certificate
	in := bufio.NewReader(pr)
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading output:", err)
			}
			break
		}
		if strings.Contains(line, "BEGIN CERTIFICATE") {
			file.WriteString(line)
			for {
				line, err := in.ReadString('\n')
				if err != nil {
					fmt.Println("Error reading certificate:", err)
					return ""
				}
				file.WriteString(line)
				if strings.Contains(line, "END CERTIFICATE") {
					break
				}
			}
		}
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		fmt.Println("Command execution failed:", err)
		return ""
	}

	fmt.Println("Certificate written to " + name)
	return name
}

// addToTrusted adds the certificate to the trusted store and updates the CA certificates.
func addToTrusted(certPath string) error {
	// Define the destination path
	destPath := "/usr/local/share/ca-certificates/" + certPath
	// Copy the certificate to the destination path
	cmdCopy := exec.Command("sudo", "cp", certPath, destPath)
	if err := cmdCopy.Run(); err != nil {
		return fmt.Errorf("error copying certificate: %v", err)
	}

	// Update the CA certificates
	cmdUpdate := exec.Command("sudo", "update-ca-certificates")
	if err := cmdUpdate.Run(); err != nil {
		return fmt.Errorf("error updating CA certificates: %v", err)
	}

	fmt.Println("Certificate added to trusted store")
	return nil
}

// fileExists checks if a file exists.
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// ftpsclientconnect connects to the FTP server via SSL/TLS.
func ftpsclientconnect(server string) {
	certificate := "server_cert_" + server + ".pem"
	if !fileExists(certificate) {
		certPath := getCertificate(server)
		if certPath == "" {
			return
		}
		if err := addToTrusted(certPath); err != nil {
			fmt.Println("Error adding certificate to trusted store:", err)
			return
		}
	} else {
		fmt.Println("Found certificate " + certificate)
	}

	// Start lftp with the commands file in a pseudo-terminal
	cmd := exec.Command("lftp", "-e", fmt.Sprintf("set ftp:ssl-force true; set ftp:ssl-protect-data true; set ssl:verify-certificate true; set ssl:ca-file %s; set ssl:check-hostname no; open ftp://%s", certificate, server))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setctty: true, Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting lftp:", err)
		return
	}

	cmd.Wait() // Wait for the lftp process to finish
}

func options(service string) bool {
	switch service {
	case "ftps":
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
