package core

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha512"
    "encoding/asn1"
    "encoding/base64"
    "errors"
    "github.com/awm/passrep/utils"
    "math/big"
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
    CryptoSalt string `sql:"not null;unique"`
    // The SigningSalt is a base64 encoded random value used when generating the user's ECDSA keys.
    SigningSalt string `sql:"not null;unique"`

    // PublicKey is the user's current public key.
    PublicKey string `sql:"not null;unique"`

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

    err = user.updatePublicKey()
    if err != nil {
        return nil, NewError(err)
    }

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

// The updatePublicKey function encodes the public key stored in the keys member and populates the PublicKey member with it.
func (this *User) updatePublicKey() error {
    if this.keys == nil {
        return errors.New("Keys not available")
    } else {
        raw, err := asn1.Marshal(*this.keys.PublicSigningKeyNoCurve())
        if err != nil {
            return err
        }

        this.PublicKey = base64.StdEncoding.EncodeToString(raw)
        return nil
    }
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
    ok, raw, err := entry.getAuthority().Verify(entry.Permissions)
    if !ok || err != nil {
        return false
    }
    // if !entry.getAuthority().Can("d", entry) {
    //     return false
    // }

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

// The makeGCM function initializes a new GCM instance with the given key.
func (this *User) makeGCM(key []byte) (cipher.AEAD, *Error) {
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
func (this *User) getEncryptionKey() []byte {
    if this.keys != nil {
        return this.keys.CryptoKey
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

    gcm, e := this.makeGCM(key)
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

    gcm, err := this.makeGCM(key)
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

// The makeSharedSecret function generates a symmetric encryption key from this user's private key and the
// other user's public key.
func (this *User) makeSharedSecret(other *User) ([]byte, error) {
    rawPubKey, err := base64.StdEncoding.DecodeString(other.PublicKey)
    if err != nil {
        return nil, NewError(err, this)
    }

    var pubKey ecdsa.PublicKey
    _, err = asn1.Unmarshal(rawPubKey, &pubKey)
    if err != nil {
        return nil, NewError(err, this)
    }

    x, y := this.keys.SigningKey.ScalarMult(pubKey.X, pubKey.Y, this.keys.SigningKey.D.Bytes())
    zero := big.NewInt(0)
    if zero.Cmp(x) == 0 && zero.Cmp(y) == 0 {
        return nil, NewError("Invalid point", this)
    }

    secret := x.Bytes()
    for i := 0; i < 10000; i++ {
        hash := sha512.Sum512(secret)
        secret = hash[:]
    }
    return secret, nil
}

// The DecryptShared function base64 decodes and decrypts data using a shared secret determined between two users.
func (this *User) DecryptShared(encrypted string, signed string, other *User) ([]byte, []byte, error) {
    rawEncrypted, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return nil, nil, NewError(err, this)
    }
    rawSigned, err := base64.StdEncoding.DecodeString(signed)
    if err != nil {
        return nil, nil, NewError(err, this)
    }

    key, err := this.makeSharedSecret(other)
    if err != nil {
        return nil, nil, err
    }

    gcm, e := this.makeGCM(key)
    if e != nil {
        return nil, nil, e
    }

    nonceLen := gcm.NonceSize()
    if len(rawEncrypted) < nonceLen {
        return nil, nil, NewError("Data too short", this)
    }

    data, err := gcm.Open(rawEncrypted[nonceLen:], rawEncrypted[:nonceLen], rawEncrypted[nonceLen:], rawSigned)
    if err != nil {
        return nil, nil, NewError(err, this)
    }

    return data, rawSigned, nil
}

// The EncryptShared function encrypts and base64 encodes data using a shared secret determined between two users.
func (this *User) EncryptShared(data []byte, sign []byte, other *User) (string, string, error) {
    key, err := this.makeSharedSecret(other)
    if err != nil {
        return "", "", err
    }

    gcm, err := this.makeGCM(key)
    if err != nil {
        return "", "", err
    }

    nonce := utils.RandomBytes(gcm.NonceSize())
    if nonce == nil {
        return "", "", NewError("Nonce generation failed", this)
    }

    raw := gcm.Seal(data, nonce, data, sign)
    result := base64.StdEncoding.EncodeToString(append(nonce, raw...))
    encoded := base64.StdEncoding.EncodeToString(sign)
    return result, encoded, nil
}

// Verify checks that this user signed the encoded blob of data.
func (this *User) Verify(signed string) (bool, []byte, error) {
    raw, err := base64.StdEncoding.DecodeString(signed)
    if err != nil {
        return false, nil, NewError(err, this)
    }

    rawKey, err := base64.StdEncoding.DecodeString(this.PublicKey)
    if err != nil {
        return false, nil, NewError(err, this)
    }

    var key SigningKey
    _, err = asn1.Unmarshal(rawKey, &key)
    if err != nil {
        return false, nil, NewError(err, this)
    }
    var ecdsaKey = ecdsa.PublicKey{elliptic.P521(), key.X, key.Y}

    var sig Signature
    remaining, err := asn1.Unmarshal(raw, &sig)
    if err != nil {
        return false, nil, NewError(err, this)
    }

    hash := sha512.Sum512(remaining)
    return ecdsa.Verify(&ecdsaKey, hash[:], sig.R, sig.S), remaining, nil
}

// Sign encodes the provided data and adds a signature generated from the user's private signing key.
func (this *User) Sign(data []byte) (string, error) {
    hash := sha512.Sum512(data)

    var err error
    var sig Signature
    sig.R, sig.S, err = ecdsa.Sign(rand.Reader, this.keys.SigningKey, hash[:])
    if err != nil {
        return "", NewError(err, this)
    }

    rawSig, err := asn1.Marshal(&sig)
    if err != nil {
        return "", NewError(err, this)
    }

    result := base64.StdEncoding.EncodeToString(append(rawSig, data...))
    return result, nil
}
