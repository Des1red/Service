package protocols

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

func Sftp() {
	for {
		fmt.Print(`
1. Setup SFTP Server.
2. Add User.
3. Delete User.
4. Stop FTP Server.
5. List FTP Users.
6. Show Server Status.
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
			listFTPUsers()
		case 6:
			showServerStatus()
		case 0:
			fmt.Println("Exiting.")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
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

	// Delete the user
	cmd := exec.Command("sudo", "userdel", "-r", user)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to delete user %s: %v\n", user, err)
		return
	}

	// Remove SFTP configuration for the user
	err = removeSFTPConfig(user)
	if err != nil {
		fmt.Printf("Error removing SFTP config for user %s: %v\n", user, err)
		return
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
			if i < len(lines) && strings.HasPrefix(lines[i], "Match") {
				continue
			}
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
			if err := setUserPassword(user); err != nil {
				fmt.Printf("Failed to set password for %s: %v\n", user, err)
				return
			}
			if err := addUserToGroup(user, "sftp"); err != nil {
				fmt.Printf("Failed to add user %s to sftp group: %v\n", user, err)
				return
			}
			if err := addSFTPConfig(user); err != nil {
				fmt.Printf("Error adding SFTP config for user %s: %v\n", user, err)
				return
			}
			createUsrDir(user)
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

func createUsrDir(user string) {
	userHomeDir := fmt.Sprintf("/var/sftp/Users/%s", user)
	ftpDir := fmt.Sprintf("%s/ftp", userHomeDir)
	filesDir := fmt.Sprintf("%s/files", ftpDir)

	// Create user's home directory with root ownership and no write permissions for others
	if err := os.MkdirAll(userHomeDir, 0755); err != nil {
		fmt.Printf("Failed to create home directory for user %s: %v\n", user, err)
		return
	}
	if err := setDirOwnershipAndPermissions(userHomeDir, "root", "root"); err != nil {
		fmt.Printf("Failed to set ownership and permissions for %s: %v\n", userHomeDir, err)
		return
	}

	// Create FTP and files directories with appropriate ownership
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		fmt.Printf("Failed to create files directory for user %s: %v\n", user, err)
		return
	}
	if err := setDirOwnershipAndPermissions(ftpDir, "nobody", "nogroup"); err != nil {
		fmt.Printf("Failed to set ownership and permissions for %s: %v\n", ftpDir, err)
		return
	}
	if err := setDirOwnershipAndPermissions(filesDir, user, user); err != nil {
		fmt.Printf("Failed to set ownership and permissions for %s: %v\n", filesDir, err)
		return
	}

	fmt.Println("\nFTP user directories set up successfully.")
}

func setDirOwnershipAndPermissions(dir, owner, group string) error {
	cmd := exec.Command("sudo", "chown", owner+":"+group, dir)
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("sudo", "chmod", "755", dir)
	if err := cmd.Run(); err != nil {
		return err
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

func listFTPUsers() {
	cmd := exec.Command("getent", "group", "sftp")
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
    PasswordAuthentication yes
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
	cmd := exec.Command("sudo", "systemctl", "status", "ssh")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Failed to get SSH service status: %v\n", err)
		return
	}
	fmt.Println(string(output))
}
