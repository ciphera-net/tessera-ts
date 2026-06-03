// Command blindindex-parity prints tessera-go's base64url-unpadded BlindIndexString for an email, so
// the TS/WASM SDK's blindIndexString can be checked for byte-exact cross-language parity. dev/CI-only.
//
// Usage: blindindex-parity <email>  → prints the blind index (base64url, unpadded) on stdout.
package main

import (
	"fmt"
	"os"

	tessera "github.com/ciphera-net/tessera-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: blindindex-parity <email>")
		os.Exit(2)
	}
	fmt.Println(tessera.BlindIndexString(os.Args[1]))
}
