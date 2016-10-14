# Guth
> Simple, Stateless, Secure

[![GoDoc](https://godoc.org/github.com/Huijari/guth?status.svg)](https://godoc.org/github.com/Huijari/guth)

Guth implements a secure stateless authentication in golang.

## Installation
`go get github.com/huijari/guth`

## Usage example
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
      log.Fatal("Decrypt", err)
    }

## Notice
This package isn't under development.

## Meta
Distributed under the MIT license. See ``LICENSE`` for more information.

[Huijari](https://github.com/huijari/)
