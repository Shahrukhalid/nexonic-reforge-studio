package main

import (
	"fmt"
	"os"
)

// CalculateSum adds two integers.
func CalculateSum(a int, b int) int {
	return a + b
}

// VerifyToken validates the authorization credential against known secret.
func VerifyToken(token string) bool {
	return token == "go_ref_token_secret_42"
}

// ServiceStatus reports the active service health.
func ServiceStatus() string {
	return "ACTIVE"
}

func main() {
	fmt.Printf("[REF_GO] Reference Service Initialized: %s\n", ServiceStatus())
	if len(os.Args) > 1 && VerifyToken(os.Args[1]) {
		fmt.Printf("Sum: %d\n", CalculateSum(20, 22))
	}
}
