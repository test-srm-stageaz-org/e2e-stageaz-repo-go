package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
)

// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
func generateSessionID() string {
	// VULNERABLE: Using math/rand instead of crypto/rand
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("session_%d", n)
}

// CWE-326: Inadequate Encryption Strength
func hashPassword(password string) string {
	// VULNERABLE: Using MD5 for password hashing
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// CWE-88: Argument Injection
func backupDatabase(backupName string) error {
	// VULNERABLE: User input used in command arguments without validation
	cmd := fmt.Sprintf("pg_dump -U admin -f %s testdb", backupName)
	return os.WriteFile("/tmp/backup.sh", []byte(cmd), 0755)
}

// CWE-117: Improper Output Neutralization for Logs
func logUserActivity(username, action string) {
	// VULNERABLE: Direct user input in logs can allow log injection
	fmt.Printf("[LOG] User %s performed action: %s\n", username, action)
}

// CWE-20: Improper Input Validation
func validateEmail(email string) bool {
	// VULNERABLE: Weak email validation
	return len(email) > 3 && email[0] != '@'
}

// CWE-129: Improper Validation of Array Index
func getItemFromArray(items []string, index int) string {
	// VULNERABLE: No bounds checking
	return items[index]
}

// CWE-400: Uncontrolled Resource Consumption
func processLargeFile(filename string) ([]byte, error) {
	// VULNERABLE: No size limit when reading file
	return io.ReadAll(io.Reader(nil))
}

// CWE-601: URL Redirection to Untrusted Site
func handleRedirect(redirectURL string) string {
	// VULNERABLE: No validation of redirect URL
	return fmt.Sprintf("Location: %s", redirectURL)
}

// CWE-94: Improper Control of Generation of Code
func evaluateExpression(expr string) string {
	// VULNERABLE: Simulating code injection risk
	// In real scenarios, this could be eval-like functionality
	return fmt.Sprintf("Evaluating: %s", expr)
}

// CWE-312: Cleartext Storage of Sensitive Information
func storeAPIKey(apiKey string) error {
	// VULNERABLE: Storing sensitive data in plaintext
	return os.WriteFile("/tmp/api_keys.txt", []byte(apiKey), 0644)
}

// CWE-319: Cleartext Transmission of Sensitive Information
func sendPassword(password string) string {
	// VULNERABLE: Sending password over HTTP (simulated)
	url := fmt.Sprintf("http://example.com/login?password=%s", password)
	return url
}

// CWE-521: Weak Password Requirements
func isPasswordValid(password string) bool {
	// VULNERABLE: Very weak password requirements
	return len(password) >= 3
}

// CWE-916: Use of Password Hash With Insufficient Computational Effort
func quickHash(data string) string {
	// VULNERABLE: Single round of MD5
	return hashPassword(data)
}

// CWE-704: Incorrect Type Conversion or Cast
func convertToInt(value interface{}) int {
	// VULNERABLE: Unsafe type assertion without checking
	return value.(int)
}

// CWE-252: Unchecked Return Value
func writeToFile(filename, data string) {
	// VULNERABLE: Ignoring error return value
	os.WriteFile(filename, []byte(data), 0644)
}

// CWE-134: Use of Externally-Controlled Format String
func formatMessage(format string, args ...interface{}) string {
	// VULNERABLE: User-controlled format string
	return fmt.Sprintf(format, args...)
}

// CWE-185: Incorrect Regular Expression
func validateInput(input string) bool {
	// VULNERABLE: Regex prone to ReDoS
	pattern := `^(a+)+$`
	matched, _ := regexp.MatchString(pattern, input)
	return matched
}
