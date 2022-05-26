package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/yargevad/filepathx"
)

var usage = strings.TrimSpace(`
safex is a tool for safely encrypting and exfiltrating sensitive data from a
target machine using https://github.com/FiloSottile/age.

safex always includes environment variables in its output.

You must specify the recipient's public key as an environment variable:
	AGE_RECIPIENT=age1szal3cwkhdseyl67ljypnjzt2zu8drfhksq0n2s4hp0r7jtrxv9sfe80mn
You can generate a new public key by running age-keygen locally.

Usage:
	safex [glob [...]]

Examples:
	safex
	safex /etc/passwd
	safex /path/to/my/storage/**/*
`)

func check(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func isFile(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	if stat.IsDir() {
		return false
	}
	return true
}

func loadRecip() (*age.X25519Recipient, error) {
	recipRaw := os.Getenv("AGE_RECIPIENT")
	if !strings.HasPrefix(recipRaw, "age1") {
		fmt.Println("RECIPIPENT must be an age public key starting with age1")
		os.Exit(1)
	}
	return age.ParseX25519Recipient(recipRaw)
}

func encryptAndPrint(recip *age.X25519Recipient, name string, value []byte) error {
	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	w, err := age.Encrypt(armorWriter, recip)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %v", err)
	}
	if _, err := w.Write(value); err != nil {
		return fmt.Errorf("failed to write to encrypted file: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted file: %v", err)
	}
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor: %v", err)
	}

	fmt.Println(name)
	fmt.Println(buf.String())
	return nil
}

func main() {
	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		fmt.Println(usage)
		os.Exit(0)
	}

	recip, err := loadRecip()
	check(err)

	encryptAndPrint(recip, "Environment variables", []byte(strings.Join(os.Environ(), "\n")))

	filesAndDirs := filepathx.Globs(os.Args[1:])
	files := []string{}
	for _, f := range filesAndDirs {
		if isFile(f) {
			files = append(files, f)
		}
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("Error reading %s: %s\n\n", f, err)
			continue
		}
		encryptAndPrint(recip, f, data)
	}
}
