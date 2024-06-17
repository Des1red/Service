package connectclient

import (
  
    "fmt"
	"os/exec"
	"syscall"
	"os"
)

// Sftpclient connects to an SFTP server.
func Sftpclient(server, sshkey string) {
    fmt.Print("\nConnect to user : ")
    var user string
    fmt.Scanln(&user)
    if user == "" {
        fmt.Print("\nNo user provided.")
        return
    }

    cmd := exec.Command("sftp", "-i", sshkey, user+"@"+server)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setctty: true, Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting sftp:", err)
		return
	}

	cmd.Wait() // Wait for the lftp process to finish
}
