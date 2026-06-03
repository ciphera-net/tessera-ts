// Command gen_go generates the Phase 4 parity vectors (blind-index.json and vault.json) using the
// authoritative tessera-go SDK. Run once to regenerate; the output is checked in under vectors/.
// The blind-index values are byte-exact (deterministic Argon2id). The vault envelopeHex values are
// randomly nonce'd on each run — only the Open direction is required for parity; the checked-in
// envelopes serve as stable test inputs for the TS verifier.
//
// Usage: go run gen_go.go [--write]
//
//	Without --write: prints the JSON to stdout.
//	With --write:    writes vectors/blind-index.json and vectors/vault.json (relative to this file).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	tessera "github.com/ciphera-net/tessera-go"
)

// blindIndexEntry is one row in blind-index.json.
type blindIndexEntry struct {
	Email              string `json:"email"`
	BlindIndexBase64Url string `json:"blindIndexBase64Url"`
}

// vaultEntry is one row in vault.json.
type vaultEntry struct {
	VaultKeyHex string `json:"vaultKeyHex"`
	Context     string `json:"context"`
	PlaintextHex string `json:"plaintextHex"`
	EnvelopeHex string `json:"envelopeHex"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	write := flag.Bool("write", false, "write JSON files to vectors/ instead of stdout")
	flag.Parse()

	// ── Blind-index vectors ──────────────────────────────────────────────────
	// Normalization is part of the parity contract (trim → lower). The emails below exercise:
	//   - canonical form
	//   - mixed-case domain
	//   - leading/trailing whitespace + plus-tag
	//   - all-upper local-part (must collapse to same index as canonical)
	//   - double-sided whitespace on mixed-case
	biEmails := []string{
		"user@example.com",
		"Alice@Example.ORG",
		" bob+tag@gmail.com ",
		"USER@EXAMPLE.COM",
		"  Alice@Example.ORG  ",
	}
	biEntries := make([]blindIndexEntry, len(biEmails))
	for i, email := range biEmails {
		biEntries[i] = blindIndexEntry{
			Email:              email,
			BlindIndexBase64Url: tessera.BlindIndexString(email),
		}
	}

	// ── Vault vectors ────────────────────────────────────────────────────────
	// Fixed, deterministic vault key (32 × 0x01). Using a non-zero, non-random key so the value is
	// obvious and easy to reproduce in a REPL. The envelopes are freshly sealed on each run; only the
	// Open direction is required for cross-language parity.
	vaultKey := make([]byte, 32)
	for i := range vaultKey {
		vaultKey[i] = 0x01
	}
	vaultKeyHex := hex.EncodeToString(vaultKey)

	type seedRow struct {
		context   string
		plaintext string
	}
	seeds := []seedRow{
		{"address", "hello vault"},
		{"totp", "JBSWY3DPEHPK3PXP"},
		{"address", `{"street":"123 Main St","city":"Zurich"}`},
	}
	vaultEntries := make([]vaultEntry, len(seeds))
	for i, s := range seeds {
		pt := []byte(s.plaintext)
		env := must(tessera.Seal(vaultKey, s.context, pt))
		// Verify immediately (belt-and-suspenders): Open must recover the original plaintext.
		recovered := must(tessera.Open(vaultKey, s.context, env))
		if string(recovered) != s.plaintext {
			fmt.Fprintf(os.Stderr, "FATAL: round-trip mismatch for context=%q\n", s.context)
			os.Exit(1)
		}
		vaultEntries[i] = vaultEntry{
			VaultKeyHex: vaultKeyHex,
			Context:     s.context,
			PlaintextHex: hex.EncodeToString(pt),
			EnvelopeHex: hex.EncodeToString(env),
		}
	}

	biJSON := must(json.MarshalIndent(biEntries, "", "  "))
	vaultJSON := must(json.MarshalIndent(vaultEntries, "", "  "))

	if !*write {
		fmt.Println("=== blind-index.json ===")
		fmt.Println(string(biJSON))
		fmt.Println("\n=== vault.json ===")
		fmt.Println(string(vaultJSON))
		return
	}

	// Write to vectors/ relative to this source file.
	_, thisFile, _, _ := runtime.Caller(0)
	vectorsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "vectors")
	writeFile := func(name string, data []byte) {
		path := filepath.Join(vectorsDir, name)
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	}
	writeFile("blind-index.json", biJSON)
	writeFile("vault.json", vaultJSON)
}
