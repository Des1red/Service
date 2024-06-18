package protocols

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"bytes"
	"archive/zip"
	"io"
	"log"

	"golang.org/x/crypto/ssh/terminal"
)

var (
    // sftp groups
    Groups = []string{"sftp"}
)
const sshdConfigPath = "/etc/ssh/sshd_config"

// this is the menu for sftp
func Sftp() {
	for {
		fmt.Print(`
1. Setup SFTP Server.
2. Add User.
3. Delete User.
4. Stop SFTP Server.
5. List SFTP Users for specific group.
6. List SFTP groups with users.
7. Add SFTP group.
8. Delete SFTP group.
9. Show Server Status.
10. Show Server Logs.
0. Exit.

sftp >> `)
		var choice int
		fmt.Scanln(&choice)
		fmt.Println()
		switch choice {
		case 1:
			setupSFTP()
		case 2:
			addSFTPUser()
		case 3:
			deleteSFTPUser()
		case 4:
			SftpStop()
		case 5:
			fmt.Print("\nGroup : ")
			var group string
			fmt.Scanln(&group)
			exists , err := groupExists(group)
			if err != nil {
				fmt.Printf("\nError : %s\n",err)
				continue
			}
			if !exists {
				fmt.Println("Group does not exists.")
				continue
			}
			listFTPUsers(group)
		case 6:
			if err := listGroups(); err != nil {
				fmt.Printf("Error listing groups: %v\n", err)
			}
		case 7:
			customSftpGroup()
		case 8:
			deleteSFTPGroup()
		case 9:
			showServerStatus()
		case 10:
			showLogs()
		case 0:
			fmt.Println("Exiting.")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Setup the server
func setupSFTP() {
	if !checkService("ssh") {
		fmt.Println("Starting SSH.")
		startService("ssh")
	} else {
		fmt.Println("SSH is already active.")
	}
	if err := ensureGroup("sftp"); err != nil {
		fmt.Println("Error ensuring group exists:", err)
	} else {
		fmt.Println("Group exists or was created successfully.")
	}
	if err := ensureDir("/var/sftp/Users"); err != nil {
		fmt.Println("Error ensuring directory exists:", err)
	}
	InitializeDb()
}

// Stop the ssh service
func SftpStop() {
	var ftp,ufw bool
	if !checkService("ssh") {
		fmt.Println("ssh is not running.")
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
		fmt.Println("Stopping SFTP server...")
		stopService("ssh")
	}
	if ufw == true {
		fmt.Println("Closing firewall ports...")
			closePorts("22/tcp")
		}

		//stopService("ufw") //in case other services are running it is recommended to not shut down ufw
	
}

// Add new sftp user
func addSFTPUser() {
	fmt.Print("New User name: ")
	var user, confirm string
	fmt.Scanln(&user)
	if user == "" {
		fmt.Println("Username cannot be empty.")
		return
	}
	for {
		fmt.Printf("Confirm user %s (y/n): ", user)
		fmt.Scanln(&confirm)
		if confirm == "y" {
			fmt.Println("Adding a new FTP user...")
			if err := createUser(user); err != nil {
				fmt.Printf("Failed to add user %s: %v\n", user, err)
				return
			}

			group := chooseGrouptoAdduser()
			if err := addUserToGroup(user, group); err != nil {
				fmt.Printf("Failed to add user %s to sftp group: %v\n", user, err)
				return
			}
			if err := createUsrDir(user); err != nil {
				fmt.Printf("Failed to create directories for user %s: %v\n", user, err)
				return
			}
			if err := generateSSHKey(user, group); err != nil {
				fmt.Printf("Failed to generate SSH key for user %s: %v\n", user, err)
				return
			}
			if err := addSFTPConfig(user); err != nil {
				fmt.Printf("Error adding SFTP config for user %s: %v\n", user, err)
				return
			}
			fmt.Println("FTP user and directories set up successfully.")

			// Add user to databse
			updatedatabase(user)

			break
		} else if confirm == "n" {
			fmt.Print("New User name: ")
			fmt.Scanln(&user)
		} else {
			fmt.Println("Type y or n")
		}
	}
}

func updatedatabase(user string) {
    fmt.Println("Adding user to database.")
    var databsepass, confirmpass string
    for {
		//prompt for pass
		fmt.Print("Enter Database password for " + user + ": ")
		bytePassword, err := terminalReadPassword()
		if err != nil {
			fmt.Println("Error reading password:", err)
			return
		}
		databsepass = strings.TrimSpace(string(bytePassword))
		fmt.Print("Confirm Password: ")
		// retype pass to confirm
		bytePassword, err = terminalReadPassword()
		if err != nil {
			fmt.Println("Error reading password:", err)
			return
		}
		confirmpass = strings.TrimSpace(string(bytePassword))
		if databsepass == confirmpass {
			break
		} else {
			fmt.Println("Passwords don't match. Try again.")
		}
	}

    // Connect to the database
    db, err := connectDB(dbPath)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    defer db.Close()

    // Add a new user
    err = AddUserToDatabase(db, user, databsepass)
    if err != nil {
        log.Printf("Error adding user: %v", err)
    } else {
        fmt.Println("User added successfully")
    }
}

// Prompts the user to enter and confirm an SSH key password
func setSSHKeyPassword() (string, error) {
	var password, confirmPass string
	for {
		fmt.Print("Enter passphrase for SSH key: ")
		bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("error reading password: %w", err)
		}
		password = strings.TrimSpace(string(bytePassword))
		fmt.Print("\nConfirm passphrase: ")
		bytePassword, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("error reading password: %w", err)
		}
		confirmPass = strings.TrimSpace(string(bytePassword))
		if password == confirmPass {
			return password, nil
		} else {
			fmt.Println("Passphrases don't match. Try again.")
		}
	}
}

// Generate the ssh key
func generateSSHKey(user, group string) error {

	// Directories
	userHomeDir := fmt.Sprintf("/var/sftp/Users/%s", user)
	userChrootDir := fmt.Sprintf("%s/home/%s", userHomeDir, user)
    sshDir := fmt.Sprintf("%s/.ssh", userChrootDir)
	authorizedKeysFile := fmt.Sprintf("%s/authorized_keys", sshDir)
	privateKeyFile := fmt.Sprintf("%s/id_rsa_%s", sshDir, user)
    publicKeyFile := fmt.Sprintf("%s/id_rsa_%s.pub", sshDir, user)
	zipFilePath := fmt.Sprintf("%s/private_key.zip", userChrootDir) // Path for the zip file


	// Ssh password
	password, err := setSSHKeyPassword()
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}
    // Generate SSH key pair
    cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-C", user, "-f", privateKeyFile, "-N", password)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    if err := cmd.Run(); err != nil {
        errMsg := fmt.Sprintf("failed to generate SSH key: %v\nstderr: %s", err, stderr.String())
        return fmt.Errorf(errMsg)
    }

    fmt.Printf("SSH key generated successfully for user %s.\n", user)
    fmt.Println("ssh-keygen output:", stdout.String())

    // Append public key to authorized_keys file
    pubKey, err := os.ReadFile(publicKeyFile)
    if err != nil {
        return fmt.Errorf("failed to read public key file: %v", err)
    }

    if err := os.WriteFile(authorizedKeysFile, pubKey, 0600); err != nil {
        return fmt.Errorf("failed to write to authorized_keys: %v", err)
    }

    // Set ownership and permissions for authorized_keys
	perm := "600"
    if err := setFileOwnershipAndPermissions(authorizedKeysFile, user, group, perm); err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys: %v", err)
    }

	// Set ownership and permissions for private key
    if err := setFileOwnershipAndPermissions(privateKeyFile, user, group, perm); err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys: %v", err)
    }

	// Set ownership and permissions for public key
	perm = "644"
    if err := setFileOwnershipAndPermissions(publicKeyFile, user, group, perm); err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys: %v", err)
    }

	// Create the zip file
    if err := createPrivateKeyZip(zipFilePath, privateKeyFile); err != nil {
        return fmt.Errorf("failed to create zip file: %v", err)
    }
    
	return nil
}

// Ownership and permissions for files
func setFileOwnershipAndPermissions(file, owner, group, perm string) error {
    cmd := exec.Command("chown", owner+":"+group, file)
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to set ownership for %s: %v", file, err)
    }

    cmd = exec.Command("chmod", perm, file)
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to set permissions for %s: %v", file, err)
    }

    return nil
}

// Ownership and permissions for directories
func setDirOwnershipAndPermissions(dir, owner, group string, perm os.FileMode) error {
    cmd := exec.Command("chown", owner+":"+group, dir)
    err := cmd.Run()
    if err != nil {
        return fmt.Errorf("failed to set ownership for %s: %v", dir, err)
    }

    err = os.Chmod(dir, perm)
    if err != nil {
        return fmt.Errorf("failed to set permissions for %s: %v", dir, err)
    }

    return nil
}

func createPrivateKeyZip(zipFilePath, privateKeyPath string) error {
    // Open the private key file
    privateKeyFile, err := os.Open(privateKeyPath)
    if err != nil {
        return fmt.Errorf("failed to open private key file: %v", err)
    }
    defer privateKeyFile.Close()

    // Create a new zip archive
    zipFile, err := os.Create(zipFilePath)
    if err != nil {
        return fmt.Errorf("failed to create zip file: %v", err)
    }
    defer zipFile.Close()

    // Create a new zip writer
    zipWriter := zip.NewWriter(zipFile)
    defer zipWriter.Close()

    // Get the file info
    privateKeyInfo, err := privateKeyFile.Stat()
    if err != nil {
        return fmt.Errorf("failed to get private key file info: %v", err)
    }

    // Create a zip file header
    privateKeyHeader, err := zip.FileInfoHeader(privateKeyInfo)
    if err != nil {
        return fmt.Errorf("failed to create zip file header: %v", err)
    }

    // Set the name of the file inside the zip archive
    privateKeyHeader.Name = "private_key.pem"

    // Create a writer for the file inside the zip archive
    privateKeyWriter, err := zipWriter.CreateHeader(privateKeyHeader)
    if err != nil {
        return fmt.Errorf("failed to create zip file writer: %v", err)
    }

    // Copy the contents of the private key file to the zip archive
    _, err = io.Copy(privateKeyWriter, privateKeyFile)
    if err != nil {
        return fmt.Errorf("failed to copy private key to zip file: %v", err)
    }

    fmt.Printf("Private key zip archive created at %s\n", zipFilePath)
    return nil
}


// User creation
func createUsrDir(user string) error {
    userHomeDir := fmt.Sprintf("/var/sftp/Users/%s", user)
    userChrootDir := fmt.Sprintf("%s/home/%s", userHomeDir, user)
    ftpDir := fmt.Sprintf("%s/public", userHomeDir)
    filesDir := fmt.Sprintf("%s/files", ftpDir)
    sshDir := fmt.Sprintf("%s/.ssh", userChrootDir)

    // Create user's home directory
    err := os.MkdirAll(userHomeDir, 0755)
    if err != nil {
        return fmt.Errorf("failed to create home directory: %v", err)
    }

    // Set ownership and permissions for user's home directory
    err = setDirOwnershipAndPermissions(userHomeDir, "root", "root", 0755)
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for home directory: %v", err)
    }

    // Create chroot home directory
    err = os.MkdirAll(userChrootDir, 0755)
    if err != nil {
        return fmt.Errorf("failed to create chroot home directory: %v", err)
    }

    // Set ownership and permissions for chroot home directory
    err = setDirOwnershipAndPermissions(userChrootDir, user, user, 0755)
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for chroot home directory: %v", err)
    }

    // Create .ssh directory
    err = os.MkdirAll(sshDir, 0700)
    if err != nil {
        return fmt.Errorf("failed to create .ssh directory: %v", err)
    }

    // Set ownership and permissions for .ssh directory
    err = setDirOwnershipAndPermissions(sshDir, user, user, 0700)
    if err != nil {
        return fmt.Errorf("failed to set ownership on .ssh directory: %v", err)
    }

    // Ensure authorized_keys file exists with the correct permissions
    authKeysFile := fmt.Sprintf("%s/authorized_keys", sshDir)
    if _, err := os.Create(authKeysFile); err != nil {
        return fmt.Errorf("failed to create authorized_keys file: %v", err)
    }

    err = setDirOwnershipAndPermissions(authKeysFile, user, user, 0600)
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys file: %v", err)
    }

    // Create FTP and files directories
    err = os.MkdirAll(filesDir, 0755)
    if err != nil {
        return fmt.Errorf("failed to create files directory: %v", err)
    }

    // Set ownership and permissions for ftp and files directories
    err = setDirOwnershipAndPermissions(ftpDir, "nobody", "nogroup", 0755)
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for ftp directory: %v", err)
    }

    err = setDirOwnershipAndPermissions(filesDir, user, user, 0755)
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for files directory: %v", err)
    }

    fmt.Println("FTP user directories set up successfully.")
    return nil
}

func createUser(username string) error {
	cmd := exec.Command("useradd", "-r", "-s", "/sbin/nologin", username)
	return cmd.Run()
}

func listFTPUsers(group string) {
	cmd := exec.Command("getent", "group", group)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Failed to list FTP users: %v\n", err)
		return
	}

	groupInfo := string(output)
	if groupInfo == "" {
		fmt.Println("No users found in sftp group.")
		return
	}

	parts := strings.Split(groupInfo, ":")
	if len(parts) < 4 {
		fmt.Println("No users found in sftp group.")
		return
	}

	users := strings.Split(parts[3], ",")
	fmt.Println("FTP Users:")
	for _, user := range users {
		fmt.Println(user)
	}
}

func addUserToGroup(username, groupName string) error {
	cmd := exec.Command("usermod", "-aG", groupName, username)
	return cmd.Run()
}

// Create Match config for user created
func addSFTPConfig(username string) error {
	configLines := fmt.Sprintf(`
Match User %s
    ChrootDirectory /var/sftp/Users/%s
    ForceCommand internal-sftp
    PasswordAuthentication no
    PermitTunnel no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitOpen none
    PubkeyAuthentication yes
    AuthorizedKeysFile /var/sftp/Users/%s/home/%s/.ssh/authorized_keys
`, username, username, username, username)

	file, err := os.OpenFile(sshdConfigPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open sshd_config: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(configLines); err != nil {
		return fmt.Errorf("failed to write to sshd_config: %w", err)
	}

	cmd := exec.Command("systemctl", "restart", "ssh")
	return cmd.Run()
}

// check if group exists if not create it
func ensureGroup(groupName string) error {
	exists, err := groupExists(groupName)
	if err != nil {
		return err
	}
	if !exists {
		return createGroup(groupName)
	}
	return nil
}

func groupExists(groupName string) (bool, error) {
	cmd := exec.Command("getent", "group", groupName)
	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func createGroup(groupName string) error {
	cmd := exec.Command("groupadd", groupName)
	return cmd.Run()
}

// check if dir exists if not create it
func ensureDir(dirName string) error {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		if err := os.MkdirAll(dirName, 0755); err != nil {
			return err
		}
		fmt.Println("SFTP Directory created.")
		if err := setDirPermissions("/var/sftp"); err != nil {
			return err
		}
		if err := os.MkdirAll("/var/sftp/Users", 0755); err != nil {
			return fmt.Errorf("error creating Files dir /var/sftp/Users: %w", err)
		}
		fmt.Println("Files dir created for /var/sftp/Users.")
	} else {
		fmt.Println("Directory exists.")
	}
	return nil
}

func setDirPermissions(dirName string) error {
	cmd := exec.Command("chown", "root:root", dirName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ownership to root for %s: %w", dirName, err)
	}
	cmd = exec.Command("chmod", "755", dirName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting permission for %s: %w", dirName, err)
	}
	return nil
}

// check if services are up
func showServerStatus() {
	if !checkService("ssh") {
		fmt.Println("\n SSH is down.")
	} else {
		fmt.Println("\n SSH is up.")
	}
}

// check the logs
func showLogs() {
	cmd := exec.Command("journalctl", "-u", "ssh", "-n", "100")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Failed to get SSH logs: %v\n", err)
		return
	}
	fmt.Println(string(output))
}

// delete user
func deleteSFTPUser() {
	fmt.Print("Enter the username to delete: ")
	var user string
	fmt.Scanln(&user)
	if user == "" {
		fmt.Println("Username cannot be empty.")
		return
	}

	fmt.Printf("Are you sure you want to delete the user %s? (y/n): ", user)
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "y" {
		fmt.Println("User deletion cancelled.")
		return
	}

	databaseremove(user)

	// Remove SSH key files for user
	err := removeSSHKeys(user)
	if err != nil {
		fmt.Printf("Error removing SSH keys for user %s: %v\n", user, err)
	} 

	// Remove SFTP configuration for the user
	err = removeSFTPConfig(user)
	if err != nil {
		fmt.Printf("Error removing SFTP config for user %s: %v\n", user, err)
		return
	}

	// Delete the user
	cmd := exec.Command("userdel", "-r", user)
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to delete user %s: %v\n", user, err)
		return
	}

	// Remove user's home directory
	err = removeUsrDir(user)
	if err != nil {
		fmt.Printf("Error removing directory for user %s: %v\n", user, err)
	} else {
		fmt.Printf("Directory removed for user %s.\n", user)
	}

	// Restart SSH service to apply changes
	cmd = exec.Command("systemctl", "restart", "ssh")
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to restart SSH service: %v\n", err)
		return
	}

	fmt.Printf("User %s deleted successfully.\n", user)
}

// func to delete user from database
func databaseremove(user string) {

		fmt.Println("Removing user from database.")
		// Connect to the database
		db, err := connectDB(dbPath)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()
	
		// Remove the user
		err = RemoveUserFromDatabase(db, user)
		if err != nil {
			log.Printf("Error removing user: %v", err)
		} else {
			fmt.Println("User removed successfully from database")
		}
	
}
// delete users directories
func removeUsrDir(user string) error {
	usrDir := fmt.Sprintf("/var/sftp/Users/%s", user)
	cmd := exec.Command("rm", "-rf", usrDir)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// Function to remove SFTP configuration for a user
func removeSFTPConfig(username string) error {
	input, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read sshd_config: %w", err)
	}

	lines := strings.Split(string(input), "\n")
	var newLines []string

	inUserBlock := false

	for _, line := range lines {
		if strings.HasPrefix(line, "Match User "+username) {
			inUserBlock = true
		}

		if inUserBlock {
			// Check if the current line is the start of another block
			if strings.HasPrefix(line, "Match ") && !strings.HasPrefix(line, "Match User "+username) {
				inUserBlock = false
			}
		}

		if !inUserBlock {
			newLines = append(newLines, line)
		}
	}

	output := strings.Join(newLines, "\n")
	err = os.WriteFile(sshdConfigPath, []byte(output), 0644)
	if err != nil {
		return fmt.Errorf("failed to write to sshd_config: %w", err)
	}

	fmt.Println("SFTP config for user deleted.")

	return nil
}

func removeSSHKeys(user string) error {
	sshDir := fmt.Sprintf("/var/sftp/Users/%s/.ssh", user)
	privateKeyFile := fmt.Sprintf("%s/id_rsa_%s", sshDir, user)
	publicKeyFile := fmt.Sprintf("%s/id_rsa_%s.pub", sshDir, user)
	authorizedKeysFile := fmt.Sprintf("%s/authorized_keys", sshDir)

	// Delete the private key file
	if err := os.Remove(privateKeyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove private key file: %v", err)
	}

	// Delete the public key file
	if err := os.Remove(publicKeyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove public key file: %v", err)
	}

	// Delete the authorized_keys file
	if err := os.Remove(authorizedKeysFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove authorized_keys file: %v", err)
	}

	fmt.Printf("SSH keys removed successfully for user %s.\n", user)
	return nil
}

// Function to delete users from a group and remove their SFTP configuration
func deleteUsersFromGroup(groupName string) error {
	// Get the list of users in the group
	cmd := exec.Command("getent", "group", groupName)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get users in group %s: %v", groupName, err)
	}

	groupInfo := string(output)
	if groupInfo == "" {
		return fmt.Errorf("no users found in group %s", groupName)
	}

	parts := strings.Split(groupInfo, ":")
	if len(parts) < 4 {
		return fmt.Errorf("invalid group information for group %s", groupName)
	}

	users := strings.Split(parts[3], ",")

	for _, user := range users {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}

		// Remove SSH keys and SFTP configuration first
		err = removeSSHKeys(user)
		if err != nil {
			fmt.Printf("Error removing SSH keys for user %s: %v\n", user, err)
		}

		err = removeSFTPConfig(user)
		if err != nil {
			fmt.Printf("Error removing SFTP config for user %s: %v\n", user, err)
		}

		// Remove user's home directory
		err = removeUsrDir(user)
		if err != nil {
			fmt.Printf("Error removing directory for user %s: %v\n", user, err)
		} else {
			fmt.Printf("Directory removed for user %s.\n", user)
		}

		// Delete the user
		cmd = exec.Command("userdel", "-r", user)
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Failed to delete user %s: %v\n", user, err)
		} else {
			fmt.Printf("Deleted user: %s\n", user)
		}
	}

	// Restart SSH service to apply changes
	cmd = exec.Command("systemctl", "restart", "ssh")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to restart SSH service: %v", err)
	}

	return nil
}

// Function to delete a group
func deleteGroup(groupName string) error {
	cmd := exec.Command("groupdel", groupName)
	return cmd.Run()
}

// Function to delete a specified SFTP group and its users
func deleteSFTPGroup() {
	fmt.Print("Enter the group name to delete: ")
	var groupName string
	fmt.Scanln(&groupName)
	if groupName == "" {
		fmt.Println("Group name cannot be empty.")
		return
	}

	fmt.Printf("Are you sure you want to delete the group %s? (y/n): ", groupName)
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "y" {
		fmt.Println("Group deletion cancelled.")
		return
	}

	err := deleteUsersFromGroup(groupName)
	if err != nil {
		fmt.Printf("Error deleting users from group: %v\n", err)
	}

	err = deleteGroup(groupName)
	if err != nil {
		fmt.Printf("Failed to delete group %s: %v\n", groupName, err)
	} else {
		fmt.Printf("Group %s deleted successfully.\n", groupName)
	}

	// Remove group from the slice (assuming Groups is a predefined slice of strings)
	indexToRemove := -1
	for i, name := range Groups {
		if name == groupName {
			indexToRemove = i
			break
		}
	}

	if indexToRemove != -1 {
		// Remove the element by slicing
		Groups = append(Groups[:indexToRemove], Groups[indexToRemove+1:]...)
	}

	// Print the updated list of Groups
	fmt.Println("Updated list of Groups:", Groups)
}

// Function to list all groups
func listGroups() error {
    cmd := exec.Command("getent", "group")
    output, err := cmd.Output()
    if err != nil {
        return fmt.Errorf("failed to get groups: %w", err)
    }

    groups := strings.Split(string(output), "\n")
    for _, groupName := range Groups {
        for _, group := range groups {
            if strings.Contains(group, groupName) {
                fmt.Printf("Group %s -->\n", groupName)
                listFTPUsers(groupName)
				fmt.Println()
                break
            }
        }
    }
    return nil
}

// create new sftp group
func customSftpGroup() error {
	fmt.Print("Enter the group name: ")
	var groupName string
	fmt.Scanln(&groupName)
	if groupName == "" {
		return fmt.Errorf("group name cannot be empty")
	}

	fmt.Printf("Are you sure you want to create the group %s? (y/n): ", groupName)
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "y" {
		fmt.Println("Group creation cancelled.")
		return nil
	}

	err := ensureGroup(groupName)
	if err != nil {
		return fmt.Errorf("failed to create group: %v", err)
	}
	Groups = append(Groups, groupName)
	fmt.Println("Group created.")
	return nil
}

// Function to prompt the user for a group name and validate its existence
func chooseGrouptoAdduser() string {
	for {
		fmt.Print("\nEnter the group name to add user (blank for sftp (default)): ")
		var groupName string
		fmt.Scanln(&groupName)
		if groupName == "" {
			groupName = "sftp"
		}

		exists, err := groupExists(groupName)
		if err != nil {
			fmt.Printf("\nError: %s\n", err)
			continue
		}

		if exists {
			fmt.Printf("\nAdding user to group: %s\n", groupName)
			return groupName
		}

		fmt.Println("Group does not exist.")
	}
}
