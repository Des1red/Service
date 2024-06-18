package protocols

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strings"
	"html/template"
    "log"
    "net/http"
    "path/filepath"
    "database/sql"
    "os/signal"
    "syscall"
    "context"
    "time"
    "sync"

    "github.com/gorilla/sessions"
    "golang.org/x/crypto/bcrypt"
)

func createOpenSSLConfigHTTPS(filePath, ipAddress string) error {
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
DNS.1   = myhttpsserver.local
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

func SSLCertHTTPS(ipAddress string) {
    certPath := "https_cert.pem"
    keyPath := "https_key.pem"
    confPath := "openssl_https.cnf"

    err := createOpenSSLConfigHTTPS(confPath, ipAddress)
    if err != nil {
        log.Fatalf("Failed to create OpenSSL configuration file: %v", err)
    }

    // Create SSL certificate
    cmd := exec.Command("openssl", "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:4096", "-keyout", keyPath, "-out", certPath, "-config", confPath)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Fatalf("Failed to create SSL Certificate: %v\nOutput: %s\n", err, output)
    }

    fmt.Println("SSL Certificate created successfully")
}

func createSSLcertHTTPS() {
    reader := bufio.NewReader(os.Stdin)

    fmt.Print("Do you want to generate an SSL certificate for HTTPS? (yes/no): ")
    choice, _ := reader.ReadString('\n')
    choice = strings.TrimSpace(choice)

    for choice != "yes" && choice != "no" {
        fmt.Print("Please type yes or no: ")
        choice, _ = reader.ReadString('\n')
        choice = strings.TrimSpace(choice)
    }

    if choice == "yes" {
        var ipAddress string
        certPath := "https_cert.pem"
        if _, err := os.Stat(certPath); os.IsNotExist(err) {
            fmt.Print("Server IP: ")
            fmt.Scanln(&ipAddress)
            SSLCertHTTPS(ipAddress)
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
                err := os.Remove(certPath)
                if err != nil {
                    log.Fatalf("Failed to delete existing certificate: %v", err)
                }
                keyPath := "https_key.pem"
                err = os.Remove(keyPath)
                if err != nil {
                    log.Fatalf("Failed to delete existing key: %v", err)
                }
                fmt.Print("Server IP: ")
                fmt.Scanln(&ipAddress)
                SSLCertHTTPS(ipAddress)
            } else {
                fmt.Println("Using existing SSL certificate.")
            }
        }
    }
}
var (
    key           = []byte("super-secret-key")
    store         = sessions.NewCookieStore(key)
    sftpUsersDir  = "/var/sftp/Users/"
    dbPath       = "/var/sftp/database.sql"
)

type HttpsUser struct {
    ID int
    Username string
    Password string
}

func getUserByUsername(db *sql.DB, username string) (*HttpsUser, error) {
    var user HttpsUser
    err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password)
    switch {
    case err == sql.ErrNoRows:
        return nil, nil
    case err != nil:
        return nil, err
    }
    return &user, nil
}

func verifyPassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func userExists(username, password string) bool {
    db, err := connectDB(dbPath)
    if err != nil {
        log.Printf("Failed to connect to database: %v", err)
        return false
    }
    defer db.Close()

    user, err := getUserByUsername(db, username)
    if err != nil {
        log.Printf("Failed to get user by username: %v", err)
        return false
    }
    if user == nil {
        return false
    }

    if err := verifyPassword(user.Password, password); err != nil {
        return false
    }
    return true
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        tmpl, err := template.ParseFiles("templates/login.html")
        if err != nil {
            log.Printf("Error parsing template: %v", err)
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, nil)
        return
    }

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        if userExists(username, password) {
            session, _ := store.Get(r, "session")
            session.Values["authenticated"] = true
            session.Values["username"] = username
            session.Save(r, w)
            http.Redirect(w, r, fmt.Sprintf("/user/%s", username), http.StatusFound)
            return
        }

        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
    }
}

func userHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    username, _ := session.Values["username"].(string)
    fmt.Fprintf(w, "Welcome to your folder, %s!\n", username)

    zipFilePath := filepath.Join(sftpUsersDir, username, "home", username, "private_key.zip")
    if _, err := os.Stat(zipFilePath); os.IsNotExist(err) {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Disposition", "attachment; filename=private_key.zip")
    w.Header().Set("Content-Type", "application/zip")
    http.ServeFile(w, r, zipFilePath)
}

// ServeMux to handle route registration and prevent conflicts
var mux *http.ServeMux
var once sync.Once

func init() {
    mux = http.NewServeMux()
}

func startHTTPSServer(srv *http.Server) {
    certFile := "https_cert.pem"
    keyFile := "https_key.pem"

    // Register routes in a thread-safe way
    once.Do(func() {
        mux.HandleFunc("/", helloHandler)
        mux.HandleFunc("/login", loginHandler)
        mux.HandleFunc("/user/", userHandler)
    })

    srv.Handler = mux

    // Start HTTPS server
    log.Println("Starting HTTPS server...")
    if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
        closePorts("443/tcp")
        log.Fatalf("ListenAndServeTLS failed: %v", err)

    }
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, HTTPS!")
}

func Https() {
    // Connect to the database
    db, err := connectDB(dbPath)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    defer db.Close()

    // Create SSL certificate for HTTPS server
    createSSLcertHTTPS()
    
    // make sure firewall is not blocking the ports
    openPorts("443/tcp")
    // Create a new HTTP server
    srv := &http.Server{
        Addr: ":443",
    }

    // Start the server in a goroutine
    go startHTTPSServer(srv)

    // Handle interrupt signals (Ctrl+C) to gracefully shutdown
    interrupt := make(chan os.Signal, 1)
    signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

    // Wait for interrupt signal
    <-interrupt

    log.Println("Received interrupt signal. Shutting down gracefully...")

    // Create a context with a timeout for the shutdown process
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    closePorts("443/tcp")

    // Gracefully shutdown the server
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatalf("Server forced to shutdown: %v", err)
    }

    log.Println("Server exiting")
}
