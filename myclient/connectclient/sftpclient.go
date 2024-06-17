package connectclient

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"

    "golang.org/x/crypto/ssh"
)

// Sftpclient connects to an SFTP server.
func Sftpclient(server string) {
    fmt.Print("\nConnect to user : ")
    var user string
    fmt.Scanln(&user)
    if user == "" {
        fmt.Print("\nNo user provided.")
        return
    }

    // Check if user configuration exists in SSH config
    if !userConfigExists(user) {
        fmt.Printf("\nNo SSH config found for user: %s", user)
        return
    }

    // Create SSH client configuration
    config, err := createSSHClientConfig(user)
    if err != nil {
        log.Fatalf("Failed to create SSH client config: %v", err)
    }

    // Connect to SSH server
    client, err := ssh.Dial("tcp", server, config)
    if err != nil {
        log.Fatalf("Failed to connect to SSH server: %v", err)
    }
    defer client.Close()

    fmt.Printf("\nConnected to %s as user %s\n", server, user)

    // Example: Perform SFTP operations here
    // Use 'client' to create an SFTP session, upload/download files, etc.
}

func createSSHClientConfig(user string) (*ssh.ClientConfig, error) {
    // Load private key file
    fmt.Print("\nPrivate key path : ")
    var privateKeyPath string
    fmt.Scanln(&privateKeyPath)
    privateKey, err := ioutil.ReadFile(privateKeyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read private key file: %v", err)
    }

    // Create signer for private key
    signer, err := ssh.ParsePrivateKey(privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %v", err)
    }

    // SSH client configuration
    config := &ssh.ClientConfig{
        User: user,
        Auth: []ssh.AuthMethod{
            // Add public key authentication method using loaded private key
            ssh.PublicKeys(signer),
        },
        // Optional: add other client config settings like Timeout, HostKeyCallback, etc.
    }

    return config, nil
}

func userConfigExists(username string) bool {
    // Path to the SSH config file
    sshConfigFile := "/etc/ssh//ssh_config"

    // Open SSH config file
    file, err := os.Open(sshConfigFile)
    if err != nil {
        log.Fatalf("Failed to open SSH config file: %v", err)
    }
    defer file.Close()

    // Create a scanner to read the file line by line
    scanner := bufio.NewScanner(file)

    // Iterate through each line of the file
    for scanner.Scan() {
        line := scanner.Text()

        // Check if line starts with 'Host' keyword and matches the username
        if strings.HasPrefix(line, "Host ") && strings.TrimSpace(line[5:]) == username {
            return true
        }
    }

    // Check for errors during scanning
    if err := scanner.Err(); err != nil {
        log.Fatalf("Error scanning SSH config file: %v", err)
    }

    return false
}
