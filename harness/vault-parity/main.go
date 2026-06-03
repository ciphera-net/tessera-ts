// Command vault-parity is a dev/CI-only helper that seals/opens a Tessera vault record using the
// tessera-go SDK, so the TS SDK's vault.ts can be checked for byte-level cross-language parity.
//
// Usage: vault-parity <seal|open> <vaultKeyHex> <context> <dataHex>
//   seal: dataHex is the plaintext  → prints the envelope as hex on stdout
//   open: dataHex is the envelope   → prints the plaintext as hex on stdout
// Errors go to stderr with a non-zero exit. This is NOT shipped — it exists only for the parity test.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	tessera "github.com/ciphera-net/tessera-go"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: vault-parity <seal|open> <vaultKeyHex> <context> <dataHex>")
		os.Exit(2)
	}
	mode, ctx := os.Args[1], os.Args[3]
	key, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad vaultKeyHex:", err)
		os.Exit(2)
	}
	data, err := hex.DecodeString(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad dataHex:", err)
		os.Exit(2)
	}

	switch mode {
	case "seal":
		env, err := tessera.Seal(key, ctx, data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seal:", err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(env))
	case "open":
		pt, err := tessera.Open(key, ctx, data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(pt))
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", mode)
		os.Exit(2)
	}
}
