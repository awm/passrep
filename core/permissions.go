package core

// Grant instances represent the grant of a particular permission by one user to another.
type Grant struct {
    // The user field is the user to which the permission has been granted.
    User string
    // The signer field is the user that is granting the permission.
    Signer string
    // The signature of the concatenated user and signer strings.
    Signature string
}

// NewGrant creates a new Grant instance and calculates the signature field.
func NewGrant(user string, signer string, signerkey []byte) *Grant {
    data = user + signer
    signature = Sign([]byte(data), signerkey)
    return &Grant{user, signer, signature}
}

// NewPreSignedGrant creates a new Grant instance using a previously calculated signature.
func NewPreSignedGrant(user string, signer string, signature string) *Grant {
    return &Grant{user, signer, signature}
}

// For determines if the grant is for the given user.
func (g *Grant) For(user string) bool {
    return (user == g.User && g.Verify())
}

// Verify checks that the signature in the grant is valid for the user and signer.
func (g *Grant) Verify() bool {
    pubkey = GetUserPubkey(g.Signer)
    return Verify(g.Signature, pubkey)
}
