package core

// Grant instances represent the grant of a particular permission by one user to another.
type Grant struct {
    // The user field is the user to which the permission has been granted.
    user string
    // The signer field is the user that is granting the permission.
    signer string
    // The signature of the concatenated user and signer strings.
    signature string
}

// NewGrant creates a new Grant instance and calculates the signature field.
func NewGrant(user string, signer string) {
    pubkey = GetUserPubkey(signer)
    data = user + signer
    signature = Sign([]byte(data), pubkey)

    return Grant{user, signer, signature}
}

// NewPreSignedGrant creates a new Grant instance using a previously calculated signature.
func NewPreSignedGrant(user string, signer string, signature string) {
    return Grant{user, signer, signature}
}

// For determines if the grant is for the given user.
func (g *Grant) For(user string) bool {
    return user == g.user
}

// Verify checks that the signature in the grant is valid for the user and signer.
func (g *Grant) Verify() bool {
    pubkey = GetUserPubkey(g.signer)
    data = user + signer
    //signature = Sign([]byte(data), pubkey)
    //return signature != nil && signature == g.signature
}
