package core

import (
    "code.google.com/p/go.crypto/pbkdf2"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha512"
    "math/big"
)

// The Keys structure holds the private cryptographic and signing keys of a user.
type Keys struct {
    // The CryptoKey field is the private symmetric encryption key for the user's own data.
    CryptoKey []byte
    // The SigningKey is the ECDSA private (and public) key used for signing entry and permission changes.
    SigningKey *ecdsa.PrivateKey
}

// PublicSigningKey provides access to the user's public ECDSA key.
func (this *Keys) PublicSigningKey() *ecdsa.PublicKey {
    return &this.SigningKey.PublicKey
}

// MakeKeys takes the password salts from the user as well as the user's password, and generates the corresponding set of private keys.
func MakeKeys(user *User, password string) (*Keys, error) {
    pwbytes := []byte(password)
    keys := new(Keys)

    salt, err := user.GetCryptoSalt()
    if err != nil {
        return nil, NewError(err, user)
    }
    keys.CryptoKey = pbkdf2.Key(pwbytes, salt, 100000, 32, sha512.New)

    curve := elliptic.P521()
    params := curve.Params()
    one := new(big.Int).SetInt64(1)
    salt, err = user.GetSigningSalt()
    if err != nil {
        return nil, NewError(err, user)
    }
    raw := pbkdf2.Key(pwbytes, salt, 100000, params.BitSize/8+8, sha512.New)
    k := new(big.Int).SetBytes(raw)
    n := new(big.Int).Sub(params.N, one)
    k.Mod(k, n)
    k.Add(k, one)

    keys.SigningKey = new(ecdsa.PrivateKey)
    keys.SigningKey.PublicKey.Curve = curve
    keys.SigningKey.D = k
    keys.SigningKey.PublicKey.X, keys.SigningKey.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())

    return keys, nil
}
