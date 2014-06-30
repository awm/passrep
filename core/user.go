package core

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "errors"
    "github.com/awm/passrep/utils"
    "strings"
    "time"
)

// The User structure represents an entity capable of interacting with password entries.
type User struct {
    // The Id is the database row identifier.
    Id  int64
    // CreatedAt is the time when the user was created.
    CreatedAt time.Time
    // UpdatedAt is the time when the user was last updated.
    UpdatedAt time.Time

    // The Name is the user's username.
    Name string
    // PublicKey is the user's current public key.
    PublicKey string

    // PrivateKey is a reference to the user's private key and is only valid while the user has an active session.
    PrivateKey *[]byte
}

const (
    // ValidPermissions is the set of allowed permissions characters.
    ValidPermissions = "rwd"
)

// Can tests whether the user has at least one of the passed in permissions on the given entry.
// The special value "*" may be used for the query to determine if the user has any permissions
// on the entry.
func (this *User) Can(query string, entry *EntryView) bool {
    raw, err := entry.getAuthority().DecryptPublic(entry.Permissions)
    if err != nil {
        return false
    }
    permissions := string(raw)
    for _, p := range permissions {
        if !strings.Contains(ValidPermissions, string(p)) {
            return false
        }
    }

    if query == "*" && len(permissions) > 0 {
        return true
    }
    for _, p := range query {
        if !strings.Contains(ValidPermissions, string(p)) {
            return false
        }
        if strings.Contains(permissions, string(p)) {
            return true
        }
    }

    return false
}

// The getGCM function initializes a new GCM instance with the given key.
func (this *User) getGCM(key []byte) (cipher.AEAD, *Error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, WrapError(err).SetUser(this)
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, WrapError(err).SetUser(this)
    }

    return gcm, nil
}

// The getPrivateKey function obtains the user's private key from the environment, if available.
func (this *User) getPrivateKey() *[]byte {
    // temporary
    return this.PrivateKey
}

// The Decrypt function decrypts a base64 encoded string that was encrypted with the user's private key.
func (this *User) Decrypt(encrypted string) ([]byte, error) {
    raw, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return nil, WrapError(err).SetUser(this).SetCode(ErrDecryption)
    }

    key := this.getPrivateKey()
    if key == nil {
        return nil, &Error{ErrDecryption, this.Name, "Private key unavailable"}
    }

    gcm, e := this.getGCM(*key)
    if e != nil {
        return nil, e.SetCode(ErrDecryption)
    }

    nonceLen := gcm.NonceSize()
    if len(raw) < nonceLen {
        return nil, &Error{ErrDecryption, this.Name, "Data too short"}
    }

    data, err := gcm.Open(raw[nonceLen:], raw[:nonceLen], raw[nonceLen:], nil)
    if err != nil {
        return nil, WrapError(err).SetUser(this).SetCode(ErrDecryption)
    }
    return data, nil
}

// The Encrypt function encrypts and base64 encodes data with the user's private key.
func (this *User) Encrypt(data []byte) (string, error) {
    key := this.getPrivateKey()
    if key == nil {
        return "", &Error{ErrEncryption, this.Name, "Private key unavailable"}
    }

    gcm, err := this.getGCM(*key)
    if err != nil {
        return "", err.SetCode(ErrEncryption)
    }

    nonce := utils.RandomBytes(gcm.NonceSize())
    if nonce == nil {
        return "", &Error{ErrEncryption, this.Name, "Nonce generation failed"}
    }

    raw := gcm.Seal(data, nonce, data, nil)
    result := base64.StdEncoding.EncodeToString(append(nonce, raw...))
    return result, nil
}

func (this *User) DecryptPublic(encrypted string) ([]byte, error) {
    return nil, errors.New("Not implemented")
}

func (this *User) EncryptPublic(data []byte) (string, error) {
    return "", errors.New("Not implemented")
}
