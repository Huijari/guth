/*
Guth implements a secure stateless authentication in golang.

Creation:
	payload := Payload{
	  Content: "6ba7b810-9dad-11d2-80b4-00c04fd430c8", // Eg. user id
	  Created: time.Now(), // Date of creation (of the token)
	}

Encrypt:
	key := []byte("0123456789abcdef") // AES key
	token, err := payload.Encrypt(key)
	if err != nil {
	  log.Fatal("Encrypt error", err)
	}

Decrypt:
	err = payload.Decrypt(token, key)
	if err != nil {
	  log.Fatal("Decrypt error", err)
	}
*/
package guth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// What the token will carry
type Payload struct {
	Content string
	Created time.Time
}

// Marshal payload to []byte
func (this Payload) MarshalBinary() (result []byte, err error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	err = encoder.Encode(this)
	result = buffer.Bytes()
	return
}

// Unmarshal payload from []byte
func (this *Payload) UnmarshalBinary(data []byte) (err error) {
	var buffer bytes.Buffer
	buffer.Write(data)

	decoded := Payload{}
	decoder := json.NewDecoder(&buffer)
	err = decoder.Decode(&decoded)
	if err != nil {
		return
	}

	this.Content = decoded.Content
	this.Created = decoded.Created
	return
}

// Generate token from payload using an AES key
func (this Payload) Encrypt(key []byte) (result []byte, err error) {
	plaintext, err := this.MarshalBinary()
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	result = ciphertext
	return
}

// Retrieve payload from token using an AES key
func (this *Payload) Decrypt(encrypted []byte, key []byte) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(encrypted) < aes.BlockSize {
		err = errors.New("ciphertext too sort")
		return
	}
	iv := encrypted[:aes.BlockSize]
	ciphertext := encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	this.UnmarshalBinary(ciphertext)
	return
}
