module tessera-vectors-gen

go 1.25.0

require github.com/ciphera-net/tessera-go v0.0.0

require (
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

// Local dev: the tessera-go SDK is a sibling clone. CI checks it out next to this repo and uses the
// same relative replace (no network fetch of the private module needed for the vectors job).
replace github.com/ciphera-net/tessera-go => ../../../tessera-go
