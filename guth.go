// Guth, stateless authentication in golang
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

var Config struct {
	period    time.Duration
	key       []byte
	separator []byte
}

type token struct {
	content   []byte
	expires   time.Time
	signature []byte
}

func generateToken(content []byte) (generated token) {
	generated = token{}
	generated.content = content
	generated.expires = time.Now().Add(Config.period)

	mac := hmac.New(sha512.New, Config.key)
	mac.Write(generated.content)
	mac.Write([]byte(generated.expires.Format(time.RFC3339)))
	generated.signature = mac.Sum(nil)
	return
}

func decodeToken(encoded string) (decoded token, err error) {
	encoded_bytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return
	}

	properties := bytes.SplitN(encoded_bytes, Config.separator, 3)
	decoded.content = properties[0]
	decoded.expires, err = time.Parse(time.RFC3339, string(properties[1]))
	if err != nil {
		return
	}
	decoded.signature = properties[2]
	return
}

func (this token) encode() (encoded string) {
	to_encode := bytes.Join([][]byte{
		this.content,
		[]byte(this.expires.Format(time.RFC3339)),
		this.signature,
	}, Config.separator)
	encoded = base64.StdEncoding.EncodeToString(to_encode)
	return
}

func (this token) validate() (content []byte, err error) {
	if this.expires.Before(time.Now()) {
		err = errors.New("Expired token")
		return
	}

	mac := hmac.New(sha512.New, Config.key)
	mac.Write(this.content)
	mac.Write([]byte(this.expires.Format(time.RFC3339)))
	signature := mac.Sum(nil)
	if bytes.Compare(this.signature, signature) != 0 {
		err = errors.New("Invalid signature")
		return
	}

	content = this.content
	return
}

// Wrap content in encoded token
func Wrap(content []byte) (wrapped string) {
	token := generateToken(content)
	wrapped = token.encode()
	return
}

// Retrieve content of encoded token
func Unwrap(wrapped string) (content []byte, err error) {
	decoded, err := decodeToken(wrapped)
	if err != nil {
		return
	}
	content, err = decoded.validate()
	return
}

func mainr() {
	id := "123"
	token := Wrap([]byte(id))
	fmt.Println(token)

	_, err := Unwrap(token)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func init() {
	Config.period, _ = time.ParseDuration("10m")
	Config.key = []byte("dc1dbbc084688dd2")
	Config.separator = []byte("#SEP#")
}
