package core

import (
    "crypto/aes"
    "crypto/cipher"
    _ "crypto/ecdsa"
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

// The getRandom function fills buffers with cryptographically secure random values.
func getRandom(buffer []byte) (err *Error) {
    _, e := rand.Read(buffer)
    if e != nil {
        return &Error{Msg: fmt.Sprintf("Random number generation failed: %s", e.Error())}
    }
    return nil
}

// Encrypt encrypts the provided data using the given key and returns the base64-encoded ciphertext.
func Encrypt(data []byte, key []byte) (string, *Error) {
    block, e := aes.NewCipher(key)
    if e != nil {
        return "", &Error{Code: ErrEncryption, Msg: e.Error()}
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    err := getRandom(iv)
    if err != nil {
        return "", err.SetCode(ErrEncryption)
    }

    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext using the given key and produces the original raw plaintext.
func Decrypt(data string, key []byte) ([]byte, *Error) {
    block, e := aes.NewCipher(key)
    if e != nil {
        return nil, &Error{Code: ErrDecryption, Msg: e.Error()}
    }

    ciphertext, e := base64.StdEncoding.DecodeString(data)
    if e != nil {
        return nil, &Error{Code: ErrDecryption, Msg: e.Error()}
    }

    iv := ciphertext[:aes.BlockSize]
    plaintext := make([]byte, len(ciphertext)-aes.BlockSize)
    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

    return plaintext, nil
}

func Sign(data []byte, key []byte) string {
    return ""
}

func Verify(data []byte, signature string, key []byte) bool {
    return true
}
