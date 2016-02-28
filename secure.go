package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"
)

type Payload struct {
	Content string
	Created time.Time
}

func (this Payload) MarshalBinary() (result []byte, err error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	err = encoder.Encode(this)
	result = buffer.Bytes()
	return
}

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

func main() {
	key := []byte("0123456789abcdef")
	user := Payload{
		"6ba7b810-9dad-11d2-80b4-00c04fd430c8",
		time.Now(),
	}

	enc, err := user.Encrypt(key)
	if err != nil {
		log.Fatal("", err)
	}
	fmt.Println(len(base64.URLEncoding.EncodeToString(enc)))

	user = Payload{}

	err = user.Decrypt(enc, key)
	if err != nil {
		log.Fatal("", err)
	}

	fmt.Println(user.Created.Format(time.RFC3339))
}
