package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

// generatePassword creates a random password of the given length.
func generatePassword(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("password length must be at least 8 characters")
	}

	var password strings.Builder
	for i := 0; i < length; i++ {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %v", err)
		}
		password.WriteByte(charset[charIndex.Int64()])
	}
	return password.String(), nil
}

// validatePassword checks if the password meets basic security criteria.
func validatePassword(password string) (bool, string) {
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()", char):
			hasSpecial = true
		}
	}

	if len(password) < 8 {
		return false, "Password must be at least 8 characters long."
	}
	if !hasUpper {
		return false, "Password must contain at least one uppercase letter."
	}
	if !hasLower {
		return false, "Password must contain at least one lowercase letter."
	}
	if !hasDigit {
		return false, "Password must contain at least one digit."
	}
	if !hasSpecial {
		return false, "Password must contain at least one special character (!@#$%^&*())."
	}

	return true, "Password is strong."
}

func main() {
	fmt.Println("Password Generator and Validator")
	fmt.Println("=================================")

	for {
		fmt.Println("\nCommands:")
		fmt.Println("  generate - Generate a new password")
		fmt.Println("  validate - Validate an existing password")
		fmt.Println("  exit     - Exit the application")
		fmt.Print("Enter a command: ")

		var command string
		fmt.Scan(&command)

		switch command {
		case "generate":
			var length int
			fmt.Print("Enter the desired password length (minimum 8): ")
			fmt.Scan(&length)

			password, err := generatePassword(length)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Generated password: %s\n", password)
			}

		case "validate":
			var password string
			fmt.Print("Enter the password to validate: ")
			fmt.Scan(&password)

			valid, message := validatePassword(password)
			if valid {
				fmt.Println("Password validation successful:", message)
			} else {
				fmt.Println("Password validation failed:", message)
			}

		case "exit":
			fmt.Println("Goodbye!")
			return

		default:
			fmt.Println("Unknown command. Please use 'generate', 'validate', or 'exit'.")
		}
	}
}
