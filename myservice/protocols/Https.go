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

    "github.com/gorilla/sessions"
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
    // Key for session management (keep this secret in a real application)
    key = []byte("super-secret-key")
    store = sessions.NewCookieStore(key)
)

// User struct to simulate a user database
type HttpsUser struct {
    Username string
    Password string
}

// Dummy user for demonstration
var dummyUser = HttpsUser{
    Username: "user1",
    Password: "password1",
}

// loginHandler handles the login page requests.
func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        tmpl, _ := template.ParseFiles("templates/login.html")
        tmpl.Execute(w, nil)
        return
    }

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        if username == dummyUser.Username && password == dummyUser.Password {
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

// userHandler handles requests to the user-specific page.
func userHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    username, _ := session.Values["username"].(string)
    fmt.Fprintf(w, "Welcome to your folder, %s!", username)
}

// startHTTPSServer starts an HTTPS server.
func startHTTPSServer() {
    http.HandleFunc("/", helloHandler)

    certFile := "https_cert.pem"
    keyFile := "https_key.pem"

    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/user/", userHandler)

    fmt.Println("Starting server at https://localhost:8080")
    log.Fatal(http.ListenAndServeTLS(":8080", certFile, keyFile, nil))
}

// Https initializes the SSL certificate creation and starts the HTTPS server.
func Https() {
    createSSLcertHTTPS()
    startHTTPSServer()
}

// helloHandler handles the root URL requests.
func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, HTTPS!")
}