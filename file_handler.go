package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// CWE-22: Path Traversal - Multiple variations
func ReadUserFile(basePath, userPath string) ([]byte, error) {
	// VULNERABLE: Simple concatenation without validation
	fullPath := basePath + "/" + userPath
	return ioutil.ReadFile(fullPath)
}

func GetFile(filename string) ([]byte, error) {
	// VULNERABLE: Using filepath.Join but no validation
	path := filepath.Join("/var/data", filename)
	return ioutil.ReadFile(path)
}

func LoadConfig(configName string) ([]byte, error) {
	// VULNERABLE: User input in file path
	configPath := fmt.Sprintf("/etc/config/%s.conf", configName)
	return ioutil.ReadFile(configPath)
}

// CWE-23: Relative Path Traversal
func AccessResource(resourcePath string) ([]byte, error) {
	// VULNERABLE: Relative path not sanitized
	return ioutil.ReadFile("./data/" + resourcePath)
}

// CWE-434: Unrestricted Upload of File with Dangerous Type
func SaveUploadedFile(filename string, content []byte) error {
	// VULNERABLE: No file type validation
	return ioutil.WriteFile("/uploads/"+filename, content, 0644)
}

// CWE-73: External Control of File Name or Path
func CopyUserFile(src, dst string) error {
	// VULNERABLE: User controls both source and destination
	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, input, 0644)
}

// CWE-409: Improper Handling of Highly Compressed Data (Zip Bomb)
func ExtractZip(zipFile string, destDir string) error {
	// VULNERABLE: No size validation before extraction
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// VULNERABLE: Also has path traversal in zip extraction
		fpath := filepath.Join(destDir, f.Name)
		
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		// VULNERABLE: No decompression size limit
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			return err
		}
	}
	return nil
}

// CWE-641: Improper Restriction of Names for Files
func CreateFileWithUserName(userName string) error {
	// VULNERABLE: Special characters in filename not sanitized
	filename := fmt.Sprintf("/tmp/%s.dat", userName)
	return ioutil.WriteFile(filename, []byte("data"), 0644)
}

// CWE-706: Use of Incorrectly-Resolved Name or Reference
func ResolveSymlink(path string) (string, error) {
	// VULNERABLE: Following symlinks without validation
	return filepath.EvalSymlinks(path)
}

// CWE-426: Untrusted Search Path
func LoadLibrary(libName string) error {
	// VULNERABLE: Loading from user-controlled path
	libPath := os.Getenv("LIB_PATH") + "/" + libName
	_, err := os.Stat(libPath)
	return err
}

// CWE-427: Uncontrolled Search Path Element
func ExecutePlugin(pluginName string) error {
	// VULNERABLE: Searching for plugin in multiple untrusted paths
	searchPaths := []string{
		"./plugins",
		"/tmp/plugins",
		os.Getenv("HOME") + "/plugins",
	}
	
	for _, path := range searchPaths {
		pluginPath := filepath.Join(path, pluginName)
		if _, err := os.Stat(pluginPath); err == nil {
			// Execute plugin (simulated)
			fmt.Println("Executing:", pluginPath)
			return nil
		}
	}
	return fmt.Errorf("plugin not found")
}

// CWE-97: Improper Neutralization of Server-Side Includes
func ProcessTemplate(templateName string) (string, error) {
	// VULNERABLE: Including files based on user input
	includePath := "/templates/" + templateName
	content, err := ioutil.ReadFile(includePath)
	if err != nil {
		return "", err
	}
	
	// Process includes (simulated SSI vulnerability)
	result := string(content)
	if strings.Contains(result, "<!--#include") {
		// VULNERABLE: Processing includes without validation
		result = strings.Replace(result, "<!--#include file=\"", "", -1)
	}
	
	return result, nil
}
