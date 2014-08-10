package core

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
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
    Name string `sql:"not null;unique"`
    // The CryptoSalt is a base64 encoded random value used when generating the user's symmetric encryption keys.
    CryptoSalt string
    // The SigningSalt is a base64 encoded random value used when generating the user's ECDSA keys.
    SigningSalt string

    // PublicKey is the user's current public key.
    PublicKey string

    // The keys field is a reference to the user's private keys and is only potentially valid while the user has an active session.
    keys *Keys `sql:"-"`
}

const (
    // ValidPermissions is the set of allowed permissions characters.
    ValidPermissions = "rwd"
)

// The NewUser function instantiates a new user object and adds the user to the database.
func NewUser(name string, password string) (*User, error) {
    user := new(User)
    user.Name = name

    cryptoSalt := utils.RandomBytes(32)
    if cryptoSalt == nil {
        return nil, NewError("RNG failure!")
    }
    user.CryptoSalt = base64.StdEncoding.EncodeToString(cryptoSalt)

    signingSalt := utils.RandomBytes(32)
    if signingSalt == nil {
        return nil, NewError("RNG failure!")
    }
    user.SigningSalt = base64.StdEncoding.EncodeToString(signingSalt)

    keys, err := MakeKeys(user, password)
    if err != nil {
        return nil, NewError(err)
    }
    user.keys = keys

    DB.Create(user)
    return user, nil
}

// LoadUser instantiates an existing user from the database.
func LoadUser(name string) (*User, error) {
    user := new(User)
    if DB.Where(&User{Name: name}).First(user).RecordNotFound() {
        return nil, NewError("User '" + name + "' not found")
    }
    return user, nil
}

// GetCryptoSalt decodes to a byte slice the base64 encoded CryptoSalt.
func (this *User) GetCryptoSalt() ([]byte, *Error) {
    raw, err := base64.StdEncoding.DecodeString(this.CryptoSalt)
    if err != nil {
        return nil, NewError(err, this)
    }
    return raw, nil
}

// GetSigningSalt decodes to a byte slice the base64 encoded SigningSalt.
func (this *User) GetSigningSalt() ([]byte, *Error) {
    raw, err := base64.StdEncoding.DecodeString(this.SigningSalt)
    if err != nil {
        return nil, NewError(err, this)
    }
    return raw, nil
}

// Can tests whether the user has at least one of the passed in permissions on the given entry.
// The special value "*" may be used for the query to determine if the user has any permissions
// on the entry.
func (this *User) Can(query string, entry *EntryView) bool {
    raw, err := entry.getAuthority().Verify(entry.Permissions)
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
        return nil, NewError(err, this)
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, NewError(err, this)
    }

    return gcm, nil
}

// The getEncryptionKey function obtains the user's private symmetric encryption key, if available.
func (this *User) getEncryptionKey() *[]byte {
    if this.keys != nil {
        return &this.keys.CryptoKey
    }
    return nil
}

// The Decrypt function decrypts a base64 encoded string that was encrypted with the user's private symmetric encryption key.
func (this *User) Decrypt(encrypted string) ([]byte, error) {
    raw, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return nil, NewError(err, this)
    }

    key := this.getEncryptionKey()
    if key == nil {
        return nil, NewError("Private key unavailable", this)
    }

    gcm, e := this.getGCM(*key)
    if e != nil {
        return nil, e
    }

    nonceLen := gcm.NonceSize()
    if len(raw) < nonceLen {
        return nil, NewError("Data too short", this)
    }

    data, err := gcm.Open(raw[nonceLen:], raw[:nonceLen], raw[nonceLen:], nil)
    if err != nil {
        return nil, NewError(err, this)
    }
    return data, nil
}

// The Encrypt function encrypts and base64 encodes data with the user's private symmetric encryption key.
func (this *User) Encrypt(data []byte) (string, error) {
    key := this.getEncryptionKey()
    if key == nil {
        return "", NewError("Private key unavailable", this)
    }

    gcm, err := this.getGCM(*key)
    if err != nil {
        return "", err
    }

    nonce := utils.RandomBytes(gcm.NonceSize())
    if nonce == nil {
        return "", NewError("Nonce generation failed", this)
    }

    raw := gcm.Seal(data, nonce, data, nil)
    result := base64.StdEncoding.EncodeToString(append(nonce, raw...))
    return result, nil
}

func (this *User) Verify(signed string) ([]byte, error) {
    // raw, err := base64.StdEncoding.DecodeString(signed)
    // if err != nil {
    //     return nil, WrapError(err).SetUser(this).SetCode(ErrEncoding)
    // }

    return nil, NewError("Not yet implemented", this)
}
