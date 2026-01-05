package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"gopkg.in/yaml.v2"
)

var db *sql.DB

// CWE-89: SQL Injection vulnerability
func getUserByID(userID string) (string, error) {
	// VULNERABLE: Direct concatenation of user input into SQL query
	query := fmt.Sprintf("SELECT username FROM users WHERE id = '%s'", userID)
	var username string
	err := db.QueryRow(query).Scan(&username)
	return username, err
}

// CWE-78: OS Command Injection vulnerability
func executeCommand(cmd string) (string, error) {
	// VULNERABLE: Executing user-supplied command without sanitization
	out, err := exec.Command("sh", "-c", cmd).Output()
	return string(out), err
}

// CWE-22: Path Traversal vulnerability
func readFile(filename string) ([]byte, error) {
	// VULNERABLE: No path sanitization allowing directory traversal
	return ioutil.ReadFile(filename)
}

// CWE-798: Hard-coded credentials
const (
	DatabasePassword = "SuperSecret123!" // Hard-coded password
	APIKey           = "sk-1234567890abcdef" // Hard-coded API key
)

// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
func validateToken(tokenString string) (*jwt.Token, error) {
	// VULNERABLE: Using none algorithm or weak signing
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// No validation of signing method
		return []byte("weak-secret"), nil
	})
}

// CWE-502: Deserialization of Untrusted Data
func parseYAML(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	// VULNERABLE: Unmarshaling untrusted YAML data
	err := yaml.Unmarshal(data, &result)
	return result, err
}

// CWE-79: Cross-site Scripting (XSS)
func renderUserContent(c *gin.Context) {
	userInput := c.Query("content")
	// VULNERABLE: Directly rendering user input without escaping
	c.Writer.Write([]byte("<html><body>" + userInput + "</body></html>"))
}

// CWE-306: Missing Authentication for Critical Function
func deleteUser(c *gin.Context) {
	// VULNERABLE: No authentication check before critical operation
	userID := c.Param("id")
	_, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "User deleted"})
}

// CWE-209: Information Exposure Through Error Messages
func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	
	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&dbPassword)
	
	if err != nil {
		// VULNERABLE: Exposing detailed error information
		c.JSON(401, gin.H{"error": fmt.Sprintf("Database error: %v", err)})
		return
	}
	
	if password != dbPassword {
		c.JSON(401, gin.H{"error": "Invalid password for user " + username})
		return
	}
	
	c.JSON(200, gin.H{"message": "Login successful"})
}

// CWE-190: Integer Overflow
func calculateTotal(quantity int, price int) int {
	// VULNERABLE: No overflow check
	return quantity * price
}

// CWE-476: NULL Pointer Dereference
func processUser(userID *string) string {
	// VULNERABLE: No nil check before dereferencing
	return *userID
}

// CWE-732: Incorrect Permission Assignment for Critical Resource
func writeSecretFile(data string) error {
	// VULNERABLE: World-readable permissions on sensitive file
	return ioutil.WriteFile("/tmp/secrets.txt", []byte(data), 0777)
}

// CWE-611: Improper Restriction of XML External Entity Reference
// Note: Go's standard XML parser is not vulnerable by default, but this demonstrates the pattern

func main() {
	// Initialize database with hard-coded credentials (CWE-798)
	var err error
	connStr := fmt.Sprintf("user=admin password=%s dbname=testdb sslmode=disable", DatabasePassword)
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		os.Exit(1)
	}
	defer db.Close()

	r := gin.Default()

	// Routes with vulnerabilities
	r.GET("/user/:id", func(c *gin.Context) {
		userID := c.Param("id")
		username, err := getUserByID(userID) // SQL Injection
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"username": username})
	})

	r.GET("/exec", func(c *gin.Context) {
		cmd := c.Query("cmd")
		output, err := executeCommand(cmd) // Command Injection
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"output": output})
	})

	r.GET("/file", func(c *gin.Context) {
		filename := c.Query("name")
		content, err := readFile(filename) // Path Traversal
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"content": string(content)})
	})

	r.GET("/render", renderUserContent) // XSS

	r.DELETE("/user/:id", deleteUser) // Missing Authentication

	r.POST("/login", login) // Information Exposure

	r.Run(":8080")
}
