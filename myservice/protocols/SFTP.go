package protocols

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"bytes"
	"golang.org/x/crypto/ssh/terminal"
)

var (
    // sftp groups
    Groups = []string{"sftp"}
)
const sshdConfigPath = "/etc/ssh/sshd_config"

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
			stopSftp()
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

func stopSftp() {
	cmd := exec.Command("sudo", "systemctl", "stop", "ssh")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to stop SSH service: %v\n", err)
	} else {
		fmt.Println("SSH service stopped successfully.")
	}
}

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
			break
		} else if confirm == "n" {
			fmt.Print("New User name: ")
			fmt.Scanln(&user)
		} else {
			fmt.Println("Type y or n")
		}
	}
}


func generateSSHKey(user, group string) error {
    privateKeyFile := fmt.Sprintf("/var/sftp/Users/%s/.ssh/id_rsa_%s", user, user)
    publicKeyFile := fmt.Sprintf("/var/sftp/Users/%s/.ssh/id_rsa_%s.pub", user, user)
    sshDir := fmt.Sprintf("/var/sftp/Users/%s/.ssh", user)
    authorizedKeysFile := fmt.Sprintf("%s/authorized_keys", sshDir)

    // Generate SSH key pair
    cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-C", user, "-f", privateKeyFile, "-N", "")
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
    if err := setFileOwnershipAndPermissions(authorizedKeysFile, user, group); err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys: %v", err)
    }

	// Set ownership and permissions for private key
    if err := setFileOwnershipAndPermissions(privateKeyFile, user, group); err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys: %v", err)
    }

	// Set ownership and permissions for public key
    if err := setFileOwnershipAndPermissions(publicKeyFile, user, group); err != nil {
        return fmt.Errorf("failed to set ownership and permissions for authorized_keys: %v", err)
    }

    return nil
}

func setFileOwnershipAndPermissions(file, owner, group string) error {
    cmd := exec.Command("sudo", "chown", owner+":"+group, file)
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to set ownership for %s: %v", file, err)
    }

    cmd = exec.Command("sudo", "chmod", "600", file)
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to set permissions for %s: %v", file, err)
    }

    return nil
}



func createUsrDir(user string) error {
    userHomeDir := fmt.Sprintf("/var/sftp/Users/%s", user)
    ftpDir := fmt.Sprintf("%s/ftp", userHomeDir)
    filesDir := fmt.Sprintf("%s/files", ftpDir)
    sshDir := fmt.Sprintf("%s/.ssh", userHomeDir)

    // Create user's home directory
    err := os.MkdirAll(userHomeDir, 0755)
    if err != nil {
        return fmt.Errorf("failed to create home directory: %v", err)
    }

    err = setDirOwnershipAndPermissions(userHomeDir, "root", "root")
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for home directory: %v", err)
    }

    // Create .ssh directory
    err = os.MkdirAll(sshDir, 0700)
    if err != nil {
        return fmt.Errorf("failed to create .ssh directory: %v", err)
    }

    // Set proper ownership and permissions
    err = setDirOwnershipAndPermissions(sshDir, user, user)
    if err != nil {
        return fmt.Errorf("failed to set ownership on .ssh directory: %v", err)
    }

    // Create FTP and files directories
    err = os.MkdirAll(filesDir, 0755)
    if err != nil {
        return fmt.Errorf("failed to create files directory: %v", err)
    }

    err = setDirOwnershipAndPermissions(ftpDir, "nobody", "nogroup")
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for ftp directory: %v", err)
    }

    err = setDirOwnershipAndPermissions(filesDir, user, user)
    if err != nil {
        return fmt.Errorf("failed to set ownership and permissions for files directory: %v", err)
    }

    fmt.Println("\nFTP user directories set up successfully.")
    return nil
}

func setDirOwnershipAndPermissions(dir, owner, group string) error {
    cmd := exec.Command("sudo", "chown", owner+":"+group, dir)
    err := cmd.Run()
    if err != nil {
        return fmt.Errorf("failed to set ownership for %s: %v", dir, err)
    }

    cmd = exec.Command("sudo", "chmod", "755", dir)
    err = cmd.Run()
    if err != nil {
        return fmt.Errorf("failed to set permissions for %s: %v", dir, err)
    }

    return nil
}

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
}

func createUser(username string) error {
	cmd := exec.Command("sudo", "useradd", "-r", "-s", "/sbin/nologin", username)
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

func setUserPassword(username string) error {
	var password, confirmPass string
	for {
		fmt.Print("Enter password for " + username + ": ")
		bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("error reading password: %w", err)
		}
		password = strings.TrimSpace(string(bytePassword))
		fmt.Print("\nConfirm Password: ")
		bytePassword, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("error reading password: %w", err)
		}
		confirmPass = strings.TrimSpace(string(bytePassword))
		if password == confirmPass {
			break
		} else {
			fmt.Println("Passwords don't match. Try again.")
		}
	}

	cmd := exec.Command("sudo", "passwd", username)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("error obtaining stdin pipe: %w", err)
	}

	go func() {
		defer stdin.Close()
		fmt.Fprintln(stdin, password)
		fmt.Fprintln(stdin, password)
	}()

	return cmd.Run()
}

func addUserToGroup(username, groupName string) error {
	cmd := exec.Command("sudo", "usermod", "-aG", groupName, username)
	return cmd.Run()
}

func addSFTPConfig(username string) error {
	configLines := fmt.Sprintf(`
Match User %s
    ChrootDirectory /var/sftp/Users/%s
    X11Forwarding no
    AllowTcpForwarding no
    ForceCommand internal-sftp
    PasswordAuthentication no
    PermitTunnel no
    AllowAgentForwarding no
    PermitOpen none
`, username, username)

	file, err := os.OpenFile(sshdConfigPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open sshd_config: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(configLines); err != nil {
		return fmt.Errorf("failed to write to sshd_config: %w", err)
	}

	cmd := exec.Command("sudo", "systemctl", "restart", "ssh")
	return cmd.Run()
}

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
	cmd := exec.Command("sudo", "groupadd", groupName)
	return cmd.Run()
}

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
	cmd := exec.Command("sudo", "chown", "root:root", dirName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ownership to root for %s: %w", dirName, err)
	}
	cmd = exec.Command("sudo", "chmod", "755", dirName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting permission for %s: %w", dirName, err)
	}
	return nil
}

func showServerStatus() {
	if !checkService("ssh") {
		fmt.Println("\n SSH is down.")
	} else {
		fmt.Println("\n SSH is up.")
	}
}

func showLogs() {
	cmd := exec.Command("sudo", "journalctl", "-u", "ssh", "-n", "100")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Failed to get SSH logs: %v\n", err)
		return
	}
	fmt.Println(string(output))
}

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

	// Remove SSH key files for user
	err := removeSSHKeys(user)
	if err != nil {
		fmt.Printf("Error removing SSH keys for user %s: %v\n", user, err)
	} else {
		fmt.Printf("SSH keys removed for user %s.\n", user)
	}

	// Remove SFTP configuration for the user
	err = removeSFTPConfig(user)
	if err != nil {
		fmt.Printf("Error removing SFTP config for user %s: %v\n", user, err)
		return
	}

	// Delete the user
	cmd := exec.Command("sudo", "userdel", "-r", user)
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
	cmd = exec.Command("sudo", "systemctl", "restart", "ssh")
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to restart SSH service: %v\n", err)
		return
	}

	fmt.Printf("User %s deleted successfully.\n", user)
}

func removeUsrDir(user string) error {
	usrDir := fmt.Sprintf("/var/sftp/Users/%s", user)
	cmd := exec.Command("sudo", "rm", "-rf", usrDir)
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

	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], "Match User "+username) {
			// Skip the lines related to the user
			for i < len(lines) && !strings.HasPrefix(lines[i], "Match") {
				i++
			}
			continue // Skip the current "Match User" line
		}
		newLines = append(newLines, lines[i])
	}

	output := strings.Join(newLines, "\n")
	err = os.WriteFile(sshdConfigPath, []byte(output), 0644)
	if err != nil {
		return fmt.Errorf("failed to write to sshd_config: %w", err)
	}

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
		cmd = exec.Command("sudo", "userdel", "-r", user)
		err = cmd.Run()
		if err != nil {
			fmt.Printf("Failed to delete user %s: %v\n", user, err)
		} else {
			fmt.Printf("Deleted user: %s\n", user)
		}
	}

	// Restart SSH service to apply changes
	cmd = exec.Command("sudo", "systemctl", "restart", "ssh")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to restart SSH service: %v", err)
	}

	return nil
}

// Function to delete a group
func deleteGroup(groupName string) error {
	cmd := exec.Command("sudo", "groupdel", groupName)
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

func chooseGrouptoAdduser() string {
	fmt.Print("\nEnter the group name to add user (blank for sftp (default)): ")
	var groupName string
	fmt.Scanln(&groupName)
	if groupName == "" {
		groupName = "sftp"
	}
	exists , err := groupExists(groupName)
	for !exists {
		exists, err = groupExists(groupName)
		if err != nil {
			fmt.Printf("\nError : %s\n",err)
		}
		fmt.Println("Group does not exists.")
		fmt.Print("\nEnter the group name to add user (blank for sftp (default)): ")
		fmt.Scanln(&groupName)
		if groupName == "" {
			groupName = "sftp"
		}
	}
	fmt.Printf("\nAdding user to group : %s\n", groupName)
	return groupName
}
