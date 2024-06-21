package protocols

import (
	"fmt"
	"os/exec"
	"os"
	"bufio"
	"log"
	"strings"
	"syscall"
	"os/signal"
	
)

type User struct {
	Name    string
	HomeDir string
	Shell   string
}

func Ftps() {
    for {
        fmt.Print("\n1. Setup Ftp Server.\n")
        fmt.Print("2. Add User.\n")
        fmt.Print("3. Delete User.\n")
        fmt.Print("4. Stop Ftp Server.\n")
        fmt.Print("5. Delete SSL Certificate and key\n")
        fmt.Print("6. Remove user access\n")
        fmt.Print("7. List FTP Users\n")
        fmt.Print("8. Show Server Status\n")
        fmt.Print("9. Monitor logs\n")
        fmt.Print("0. Exit\n")
        fmt.Print("\nftps >> ")
        var choice int
        fmt.Scanln(&choice)
        switch choice {
        case 1:
            ftpSetup()
        case 2:
            ftpAddUser()
        case 3:
            ftpDel()
        case 4:
            ftpStop()
        case 5:
            DelSSLCert()
        case 6:
            var user string
            fmt.Print("User : ")
            fmt.Scanln(&user)
            if user == "" {
                fmt.Print("No user provided\n")
                break
            }
            removeUserFromVSFTPDUserList(user)
        case 7:
            fmt.Println()
            usersFromlist()
            fmt.Println()
        case 8:
            fmt.Print("\n\n Server Status \n\n")
            if checkService("ufw") {
                fmt.Println("Firewall is active.")
            } else {
                fmt.Println("Firewall is down.")
            }
            if checkService("vsftpd") {
                fmt.Println("FTPS service is up.")
            } else {
                fmt.Println("FTPS service is down.")
            }
            fmt.Println()
        case 9:
            monitorlogs()
        case 0:
            fmt.Print("Bye!")
            return
        default:
            fmt.Println("Invalid option.")
        }
    }
}

func monitorlogs() {
		// Start tailing the log file
		cmd := exec.Command("tail", "-f", "/var/log/vsftpd.log")
		
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Println("Error creating StdoutPipe:", err)
			return
		}
	
		stderr, err := cmd.StderrPipe()
		if err != nil {
			fmt.Println("Error creating StderrPipe:", err)
			return
		}
	
		if err := cmd.Start(); err != nil {
			fmt.Println("Error starting log monitoring:", err)
			return
		}
	
		// Create a channel to listen for OS signals
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	
		// Create a goroutine to handle the OS signals
		go func() {
			// Wait for a signal
			<-sig
	
			// Handle the signal (Ctrl+C)
			fmt.Println("Received Ctrl+C, stopping monitoring...")
			err := cmd.Process.Signal(syscall.SIGTERM)
			if err != nil {
				fmt.Println("Error stopping monitoring:", err)
			} else {
				fmt.Println("Monitoring process ended successfully.")
			}
		}()
	
		// Create a goroutine to print the log output
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		}()
	
		// Create a goroutine to print the log errors
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		}()
	
		// Wait for the command to finish
		if err := cmd.Wait(); err != nil {
			fmt.Println("Log monitoring ended with error:", err)
		}		
}

func DelSSLCert() {
	files := []string{
		"/etc/ssl/private/vsftpd.pem",
		"/etc/ssl/private/openssl.cnf",
		"/usr/local/share/ca-certificates/mycompany.crt",
	}

	for _, file := range files {
		cmd := exec.Command("rm", file)
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Failed to delete %s: %v\n", file, err)
		} else {
			fmt.Printf("Successfully deleted %s\n", file)
		}
	}
}

func usersFromlist() {
	users := listFtpUsers()
				if len(users) == 0 {
					fmt.Println("No users with nologin shell and FTP directory found.")
					return
				}

				fmt.Println("Users with nologin shell and FTP directory:")
				for _, user := range users {
					fmt.Println(user.Name)
				}
}

func listFtpUsers() []User {
	// Open the /etc/passwd file
	file, err := os.Open("/etc/passwd")
	if err != nil {
		fmt.Println("Error opening /etc/passwd:", err)
		return nil
	}
	defer file.Close()

	// Scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	var users []User

	// Read /etc/passwd file line by line
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		homeDir := parts[5]
		shell := parts[6]

		if strings.HasSuffix(shell, "nologin") {
			users = append(users, User{Name: username, HomeDir: homeDir, Shell: shell})
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading /etc/passwd:", err)
		return nil
	}

	// Check for FTP directories and collect matching users
	var ftpUsers []User
	for _, user := range users {
		ftpDir1 := fmt.Sprintf("/srv/ftp/%s", user.Name)
		ftpDir2 := fmt.Sprintf("%s/ftp", user.HomeDir)

		if directoryExists(ftpDir1) || directoryExists(ftpDir2) {
			ftpUsers = append(ftpUsers, user)
		}
	}

	return ftpUsers
}

// Function to check if a directory exists
func directoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func removeUserFromVSFTPDUserList(username string) error {
	filePath := "/etc/vsftpd.user_list"
    // Read the file contents
    file, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("failed to open file: %v", err)
    }
    defer file.Close()

    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.TrimSpace(line) != username {
            lines = append(lines, line)
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Errorf("error reading file: %v", err)
    }

    // Write the updated contents back to the file
    file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
    if err != nil {
        return fmt.Errorf("failed to open file for writing: %v", err)
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    for _, line := range lines {
        _, err = writer.WriteString(line + "\n")
        if err != nil {
            return fmt.Errorf("error writing to file: %v", err)
        }
    }

    err = writer.Flush()
    if err != nil {
        return fmt.Errorf("error flushing writer: %v", err)
    }

    return nil
}

func ftpDel() {
    users := listFtpUsers()
    if len(users) == 0 {
        fmt.Println("No users with nologin shell and FTP directory found.")
        return
    }

    fmt.Println("Users with nologin shell and FTP directory:")
    for _, user := range users {
        fmt.Println(user.Name)
    }

    var user, confirm string
    fmt.Print("\n\nDelete User: ")
    fmt.Scanln(&user)
	if user == "" {
		fmt.Println("Username cannot be empty.")
		return
	}
    for {
        fmt.Printf("\nConfirm delete user %s (y/n): ", user)
        fmt.Scanln(&confirm)
        if confirm == "y" {
			removeUserFromVSFTPDUserList(user)
            cmd := exec.Command("userdel", user)
            err := cmd.Run()
            if err != nil {
                fmt.Printf("Failed to delete user: %s. Error: %v\n", user, err)
                break // Exit the loop if user deletion failed
            } else {
                fmt.Printf("Deleted User: %s\n", user)
            }

            cmd = exec.Command("rm", "-rf", "/home/"+user)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("Failed to delete user directory: /home/%s. Error: %v\n", user, err)
                break // Exit the loop if directory deletion failed
            } else {
                fmt.Printf("Deleted User directory: /home/%s\n", user)
            }
            
            // Both user and directory deletion were successful, break out of the loop
            break
        } else if confirm == "n" {
            fmt.Print("\n\nDelete User: ")
            fmt.Scanln(&user)
        } else {
            fmt.Println("Type y/n.")
        }
    }
}

// addUserToFile checks if the file exists and adds the user to the file.
func addUserToFile(filePath, user string) error {
	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// If the file doesn't exist, create it
		_, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create file: %v", err)
		}
	}

	// Open the file for appending
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Check if the user already exists in the file
	fileRead, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	defer fileRead.Close()

	scanner := bufio.NewScanner(fileRead)
	userExists := false
	for scanner.Scan() {
		if scanner.Text() == user {
			userExists = true
			break
		}
	}

	if userExists {
		fmt.Printf("User %s already exists in %s\n", user, filePath)
		return nil
	}

	// Add the user to the file
	_, err = file.WriteString(user + "\n")
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	fmt.Printf("User %s added to %s successfully\n", user, filePath)
	return nil
}

func ftpAddUser() {
	fmt.Print("New User name: ")
	var user, confirm string
	fmt.Scanln(&user)
	if user == "" {
		fmt.Println("Username cannot be empty.")
		return
	}
	for {
		fmt.Printf("\nConfirm user %s (y/n): ", user)
		fmt.Scanln(&confirm)
		if confirm == "y" {
			fmt.Println("Adding a new FTP user...")
			
			// Call the addUserToFile function
			filePath := "/etc/vsftpd.user_list"
			err := addUserToFile(filePath, user)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			// Add the user with no login shell
			cmd := exec.Command("useradd", "-r", "-s", "/sbin/nologin", user)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to add user %s: %v\n", user, err)
				return
			} else {
				fmt.Printf("User %s added successfully.\n", user)
			}

			homeDir := "/home/" + user

			// Ensure home directory is created
			cmd = exec.Command("mkdir", "-p", homeDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to create home directory for user %s: %v\n", user, err)
				return
			} else {
				fmt.Printf("Created home directory for user %s: %s\n", user, homeDir)
			}

			// Set ownership and permissions for home directory
			cmd = exec.Command("chown", user+":"+user, homeDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to set ownership for /home/%s: %v\n", user, err)
				return
			} else {
				fmt.Printf("Ownership set for home directory successful.\n")
			}

			cmd = exec.Command("chmod", "755", homeDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to set permissions for /home/%s: %v\n", user, err)
				return
			} else {
				fmt.Printf("Permissions set for home directory successful.\n")
			}

			// Creating FTP directory at home for user
			ftpDir := homeDir + "/ftp"
			if _, err = os.Stat(ftpDir); os.IsNotExist(err) {
				cmd = exec.Command("mkdir", "-p", ftpDir)
				err = cmd.Run()
				if err != nil {
					fmt.Printf("Failed to create ftp directory for user %s: %v\n", user, err)
					return
				} else {
					fmt.Printf("Created ftp directory for user %s: %s\n", user, ftpDir)
				}
			} else {
				fmt.Println("FTP directory already exists.")
			}

			// Set ownership and permissions for FTP directory
			cmd = exec.Command("chown", "nobody:nogroup", ftpDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to set ownership for /home/%s/ftp: %v\n", user, err)
				return
			} else {
				fmt.Printf("Ownership set for FTP directory successful.\n")
			}

			cmd = exec.Command("chmod", "755", ftpDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to set permissions for /home/%s/ftp: %v\n", user, err)
				return
			} else {
				fmt.Printf("Permissions set for FTP directory successful.\n")
			}

			// Create the files directory for the user
			filesDir := ftpDir + "/files"
			cmd = exec.Command("mkdir", "-p", filesDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to create directory %s: %v\n", filesDir, err)
				return
			} else {
				fmt.Printf("Files directory creation for FTP directory successful.\n")
			}

			// Assign ownership of the files directory to the new user
			cmd = exec.Command("chown", user+":"+user, filesDir)
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to set ownership for %s: %v\n", filesDir, err)
				return
			} else {
				fmt.Printf("Ownership set for FTP files directory successful.\n")
			}

			// Set up user password
			var password, confirmpass string
			for {
				//prompt for pass
				fmt.Print("Enter password for " + user + ": ")
				bytePassword, err := terminalReadPassword()
				if err != nil {
					fmt.Println("Error reading password:", err)
					return
				}
				password = strings.TrimSpace(string(bytePassword))
				fmt.Print("Confirm Password: ")
				// retype pass to confirm
				bytePassword, err = terminalReadPassword()
				if err != nil {
					fmt.Println("Error reading password:", err)
					return
				}
				confirmpass = strings.TrimSpace(string(bytePassword))
				if password == confirmpass {
					break
				} else {
					fmt.Println("Passwords don't match. Try again.")
				}
			}
			cmd = exec.Command("passwd", user)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				fmt.Printf("Error obtaining stdin pipe: %v\n", err)
				return
			}

			// Write the new password to the command's standard input
			go func() {
				defer stdin.Close()
				fmt.Fprintln(stdin, password)
				fmt.Fprintln(stdin, password) // Re-enter the password for confirmation
			}()

			// Run the command
			err = cmd.Run()
			if err != nil {
				fmt.Printf("Failed to set password for %s: %v\n", user, err)
				return
			}

			fmt.Println("FTP user and directories set up successfully.")
			break
		} else if confirm == "n" {
			fmt.Print("\nNew User name: ")
			fmt.Scanln(&user)
		} else {
			fmt.Println("Type y or n")
		}
	}
}

func ftpStop() {
	var ftp,ufw bool
	if !checkService("vsftpd") {
		fmt.Println("vsftpd is not running.")
		ftp = false
	} else {
		ftp = true
	}

	if !checkService("ufw") {
		fmt.Println("ufw is not running.")
		ufw = false
	} else {
		ufw = true
	}

	if ftp == true {
		fmt.Println("Stopping FTP server...")
		stopService("vsftpd")
	}
	if ufw == true {
		fmt.Println("Closing firewall ports...")
		ports := []string{"20/tcp", "21/tcp", "40000:50000/tcp", "990/tcp"}
		for _, port := range ports {
			closePorts(port)
		}

		//stopService("ufw") //in case other services are running it is recommended to not shut down ufw
	}
}

// ModifyServiceFilepath updates the vsftpd service file path and reloads the daemon
func ModifyServiceFilepath() {
	// Update the service file
	cmd := exec.Command("sed", "-i", "s|ExecStart=/usr/sbin/vsftpd.*|ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf.origin|", "/lib/systemd/system/vsftpd.service")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to change vsftpd service file path:", err)
		return
	} else {
		fmt.Println("Changed vsftpd service file path successfully")
	}

	// Reload systemd daemon
	cmd = exec.Command("systemctl", "daemon-reload")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to reload systemd:", err)
	} else {
		fmt.Println("Reloaded systemd successfully")
	}
}

// ConfigureVSFTPD creates the vsftpd configuration file if it does not exist
func ConfigureVSFTPD() {
	filepath := "/etc/vsftpd.conf.origin"
	// Check if file exists
	if _, err := os.Stat(filepath); err == nil {
		fmt.Printf("File %s exists.\n", filepath)
		return
	} else if os.IsNotExist(err) {
		fmt.Printf("File %s does not exist.\n", filepath)
		fmt.Println("Creating File...")
		file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer file.Close()

		// Create a bufio.Writer to write to the file
		writer := bufio.NewWriter(file)

		// Write new lines to the file
		lines := []string{
			"listen=NO",
			"listen_ipv6=YES",
			"anonymous_enable=NO",
			"local_enable=YES",
			"write_enable=YES",
			"local_umask=022",
			"dirmessage_enable=YES",
			"use_localtime=YES",
			"xferlog_enable=YES",
			"connect_from_port_20=YES",
			"chroot_local_user=YES",
			"allow_writeable_chroot=YES",
			"secure_chroot_dir=/var/run/vsftpd/empty",
			"pam_service_name=vsftpd",
			"force_dot_files=YES",
			"pasv_min_port=40000",
			"pasv_max_port=50000",
			"userlist_deny=NO",
			"userlist_enable=YES",
			"userlist_file=/etc/vsftpd.user_list",
			"log_ftp_protocol=YES",
			"xferlog_enable=YES",
			"",
			"user_sub_token=$USER",
			"local_root=/home/$USER/ftp",
			"",
			"ssl_enable=YES",
			"rsa_cert_file=/etc/ssl/private/vsftpd.pem",
			"rsa_private_key_file=/etc/ssl/private/vsftpd.pem",
			"allow_anon_ssl=NO",
			"force_local_data_ssl=YES",
			"force_local_logins_ssl=YES",
			"ssl_tlsv1=YES",
			"ssl_sslv2=NO",
			"ssl_sslv3=NO",
			"require_ssl_reuse=NO",
			"ssl_ciphers=HIGH",
		}

		for _, line := range lines {
			_, err := writer.WriteString(line + "\n")
			if err != nil {
				fmt.Println("Error writing to file:", err)
				return
			}
		}

		// Flush any buffered data to ensure it's written to the file
		err = writer.Flush()
		if err != nil {
			fmt.Println("Error flushing writer:", err)
			return
		}

		fmt.Println("Lines added to file successfully.")

		// Modify service file path and reload systemd daemon
		ModifyServiceFilepath()

	} else {
		fmt.Printf("Error checking file %s: %v\n", filepath, err)
	}
}

// createOpenSSLConfig creates the OpenSSL configuration file with strong settings
func createOpenSSLConfig(filePath,ipAddress string) error {
	if _, err := os.Stat(filePath); err == nil {
		fmt.Printf("Configuration file %s already exists.\n", filePath)
		return nil
	}

	configContent := fmt.Sprintf(`
[ req ]
default_bits        = 4096
default_md          = sha512
distinguished_name  = req_distinguished_name
req_extensions      = req_ext
x509_extensions     = v3_ca
string_mask         = utf8only
prompt              = no

[ req_distinguished_name ]
countryName                     = US
stateOrProvinceName             = California
localityName                    = San Francisco
organizationName                = Personal
organizationalUnitName          = IT
commonName                      = %s
emailAddress                    = admin@kali

[ req_ext ]
subjectAltName = @alt_names

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
extendedKeyUsage = serverAuth, clientAuth

[ alt_names ]
DNS.1   = myftpserver.local
IP.1    = %s
`, ipAddress, ipAddress)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(configContent)
	if err != nil {
		return err
	}

	fmt.Printf("OpenSSL configuration file created at %s\n", filePath)
	return nil
}

func SSLCert(ipAddress string) {
	pemPath := "/etc/ssl/private/vsftpd.pem"
	bakPath := pemPath + ".bak"
	confPath := "/etc/ssl/private/openssl.cnf"

	err := createOpenSSLConfig(confPath, ipAddress)
	if err != nil {
		log.Fatalf("Failed to create OpenSSL configuration file: %v", err)
	} else {
		fmt.Printf("Created OpenSSL configuration file\n")
	}

	// Set permissions for the configuration file
	if err := os.Chmod(confPath, 0644); err != nil {
		log.Fatalf("Failed to set permissions for configuration file: %v", err)
	}

	// Backup existing certificate file
	if _, err := os.Stat(pemPath); err == nil {
		if err := os.Rename(pemPath, bakPath); err != nil {
			log.Fatalf("Failed to backup existing file: %v", err)
		}
		fmt.Printf("Existing file backed up to %s\n", bakPath)
	}

	// Create SSL certificate
	cmd := exec.Command("openssl", "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:4096", "-keyout", pemPath, "-out", pemPath, "-config", confPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to create SSL Certificate: %v\nOutput: %s\n", err, output)
	}

	// Set permissions for the certificate file
	if err := os.Chmod(pemPath, 0600); err != nil {
		log.Fatalf("Failed to set permissions for certificate file: %v", err)
	}

	fmt.Println("SSL Certificate created successfully")


	// Add the self-signed certificate to the trusted certificates
	err = addSelfSignedCertToTrusted(pemPath)
	if err != nil {
		log.Fatalf("Failed to add SSL Certificate to trusted store: %v", err)
	}
}

func addSelfSignedCertToTrusted(certPath string) error {
	cmd := exec.Command("cp", certPath, "/usr/local/share/ca-certificates/mycompany.crt")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy certificate: %v\nOutput: %s\n", err, output)
	}

	cmd = exec.Command("update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to update trusted certificates: %v\nOutput: %s\n", err, output)
	}

	fmt.Println("Self-signed certificate added to trusted certificates")
	return nil
}

func createSSLcert() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Do you want to generate an SSL certificate? (yes/no): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	for choice != "yes" && choice != "no" {
		fmt.Print("Please type yes or no: ")
		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
	}

	if choice == "yes" {
		var ipAddress string
		pemPath := "/etc/ssl/private/vsftpd.pem"
		bakPath := pemPath + ".bak"
		if _, err := os.Stat(pemPath); os.IsNotExist(err) {
			fmt.Print("Server IP: ")
			fmt.Scanln(&ipAddress)
			SSLCert(ipAddress)
		} else {
			fmt.Println("SSL certificate already exists.")
			fmt.Print("Would you like to generate a new certificate? (yes/no): ")
			choice, _ = reader.ReadString('\n')
			choice = strings.TrimSpace(choice)

			for choice != "yes" && choice != "no" {
				fmt.Print("Please type yes or no: ")
				choice, _ = reader.ReadString('\n')
				choice = strings.TrimSpace(choice)
			}

			if choice == "yes" {
				fmt.Println()
				err := os.Rename(pemPath, bakPath)
				if err != nil {
					fmt.Println("Failed to backup existing file:", err)
					return
				}
				fmt.Println("Existing SSL Certificate backed up to:", bakPath)
				cmd := exec.Command("rm", "/etc/ssl/private/openssl.cnf")
				err = cmd.Run()
				if err == nil {
					fmt.Println("Old SSL certificate deleted. Making a new one")
				}
				fmt.Print("Server IP: ")
				fmt.Scanln(&ipAddress)
				SSLCert(ipAddress)
			} else {
				fmt.Println("Using existing SSL certificate.")
			}
		}
	}
}
// Check if /sbin/nologin is in /etc/shells
func checkAndAddNoLogin() error {
    const noLoginShell = "/sbin/nologin"
    const shellsFile = "/etc/shells"

    // Open /etc/shells
    file, err := os.Open(shellsFile)
    if err != nil {
        return fmt.Errorf("could not open %s: %v", shellsFile, err)
    }
    defer file.Close()

    // Check if /sbin/nologin is in the file
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        if strings.TrimSpace(scanner.Text()) == noLoginShell {
            // /sbin/nologin already exists in /etc/shells
            return nil
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Errorf("error reading %s: %v", shellsFile, err)
    }

    // If /sbin/nologin is not found, append it using sudo
    cmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf("echo %q >> %s", noLoginShell, shellsFile))
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to append %q to %s: %v", noLoginShell, shellsFile, err)
    }

    return nil
}

func ftpSetup() {
	//add nologin shell to /etc/shells
	if err := checkAndAddNoLogin(); err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Println("/sbin/nologin is ensured to be in /etc/shells")
    }
	createSSLcert()
	fmt.Println("Configuring vsftpd file...")
	ConfigureVSFTPD()
	services := []string{"vsftpd", "ufw"}
	for _, service := range services {
		SetUpService(service)
	}
	fmt.Println("Setting up firewall...")
	openPorts("20/tcp")
	openPorts("21/tcp")
	openPorts("40000:50000/tcp")
	openPorts("990/tcp")
	
	cmd := exec.Command("ufw", "enable")
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to enable firewall: %v\n", err)
	} else {
		fmt.Println("Firewall enabled successfully.")
	}

	fmt.Println("\nFirewall Status:")
	cmd = exec.Command("ufw", "status")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Failed to show status: %v\n", err)
	} else {
		fmt.Printf("%s\n", output)
	}
}

