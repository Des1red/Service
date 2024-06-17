package protocols

import (
    "database/sql"
    "log"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func InitializeDb() {
    db, err := sql.Open("sqlite3", "/var/sftp/database.sql")
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    defer db.Close()

    createTableSQL := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );`

    _, err = db.Exec(createTableSQL)
    if err != nil {
        log.Fatalf("Failed to create table: %v", err)
    }

    log.Println("Database initialized successfully")
}

// edit database

func connectDB(dbPath string) (*sql.DB, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }
    if err := db.Ping(); err != nil {
        db.Close()
        return nil, err
    }
    return db, nil
}

func hashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedPassword), nil
}

// Add user
func AddUserToDatabase(db *sql.DB, username, password string) error {
    hashedPassword, err := hashPassword(password)
    if err != nil {
        return err
    }

    stmt, err := db.Prepare("INSERT INTO users(username, password) VALUES(?, ?)")
    if err != nil {
        return err
    }
    defer stmt.Close()

    _, err = stmt.Exec(username, hashedPassword)
    if err != nil {
        return err
    }

    return nil
}

// Remove User

func RemoveUserFromDatabase(db *sql.DB, username string) error {
    stmt, err := db.Prepare("DELETE FROM users WHERE username = ?")
    if err != nil {
        return err
    }
    defer stmt.Close()

    _, err = stmt.Exec(username)
    if err != nil {
        return err
    }

    return nil
}

