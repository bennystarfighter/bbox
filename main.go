package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if len(os.Args) != 2 {
		println(`Supply a path to one file.`)
		return
	}
	println(os.Args[1])
	if f, err := os.Stat(os.Args[1]); err == nil {
		name := filepath.Ext(f.Name())

		file, err := os.Open(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		if name == ".bbox" {
			DecodeBbox(file)
		} else {
			EncodeBbox(file)
		}
	} else if os.IsNotExist(err) {
		fmt.Println(os.Args[1] + " does not exist!")
	} else {
		fmt.Println("Schrodinger: file may or may not exist.")
	}
}

func DecodeBbox(file *os.File) {
	fmt.Print("Enter encryption password: ")
	userPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	MasterKey := sha256.Sum256([]byte(userPassword))

	nonce := make([]byte, 32)

	encryptedFIle, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	nonce = encryptedFIle[0:31]
	fileContent := bytes.NewBuffer(encryptedFIle[32:])

	var key [32]byte
	kdf := hkdf.New(sha256.New, MasterKey[:], nonce, nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err) // add error handling
		return
	}

	filename := strings.TrimSuffix(file.Name(), ".bbox")

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = sio.Decrypt(f, fileContent, sio.Config{Key: key[:], MinVersion: uint8(20), MaxVersion: uint8(20)})
	if err != nil {
		log.Fatal(err)
	}

}

func EncodeBbox(file *os.File) {
	fmt.Print("Enter encryption password: ")
	userPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	newMasterKey := sha256.Sum256([]byte(userPassword))

	f, err := os.Create(file.Name() + ".bbox")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// generate a random nonce to derive an encryption key from the master key
	// this nonce must be saved to be able to decrypt the data again - it is not
	// required to keep it secret
	var nonce [32]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		fmt.Printf("Failed to read random data: %v", err) // add error handling
		return
	}

	_, err = f.Write(nonce[:])
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write([]byte("\n---\n"))
	if err != nil {
		log.Fatal(err)
	}

	// derive an encryption key from the master key and the nonce
	var key [32]byte
	kdf := hkdf.New(sha256.New, newMasterKey[:], nonce[:], nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err) // add error handling
		return
	}

	_, err = sio.Encrypt(f, file, sio.Config{Key: key[:], MinVersion: uint8(20), MaxVersion: uint8(20)})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Encrypted file stored as: " + f.Name())
}
