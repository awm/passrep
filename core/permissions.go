package core

// Grant instances represent the grant of a particular permission by one user to another.
type Grant struct {
    // The ID field is the ID of entry that this grant is for.
    Id  string
    // The user field is the user to which the permission has been granted.
    User string
    // The signer field is the user that is granting the permission.
    Signer string
    // The signature of the concatenated user and signer strings.
    Signature string
}

// NewGrant creates a new Grant instance and calculates the signature field.
func NewGrant(id string, user string, signer string, signerkey []byte) *Grant {
    data := id + user + signer
    signature := Sign([]byte(data), signerkey)
    return &Grant{id, user, signer, signature}
}

// For determines if the grant is for the given user.
func (this *Grant) For(id string, user string) bool {
    return (id == this.Id && user == this.User && this.Verify())
}

// Verify checks that the signature in the grant is valid for the user and signer.
func (this *Grant) Verify() bool {
    pubkey := GetUserPubkey(this.Signer)
    data := this.Id + this.User + this.Signer
    return Verify([]byte(data), this.Signature, pubkey)
}
