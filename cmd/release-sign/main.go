// Подписание списка контрольных сумм; закрытый ключ передаётся только через env.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"log"
	"os"
)

func main() {
	manifest := flag.String("manifest", "dist/SHA256SUMS", "Manifest file")
	output := flag.String("out", "dist/SHA256SUMS.sig", "Signature file")
	flag.Parse()
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("RELEASE_SIGNING_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatal("RELEASE_SIGNING_KEY is missing or invalid")
	}
	private := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) != "MeXlQXEJ/oazafi9vpo3hdUhxmpKB8fIHsSv6oGNCRM=" {
		log.Fatal("signing key does not match the public update key")
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		log.Fatal(err)
	}
	sig := ed25519.Sign(private, data)
	if err = os.WriteFile(*output, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil {
		log.Fatal(err)
	}
}
