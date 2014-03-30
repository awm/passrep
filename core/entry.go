package core

import (
    "bytes"
    "encoding/json"
    "image"
    _ "image/png"
    "sync"
    "time"
)

// Entry instances represent one user's view of a password database entry.
// Most fields are kept encrypted until they need to be accessed.
type Entry struct {
    // The id string is the unique identifier for the entry, and ties together the individual views into the entry of each user.
    id  string
    // The modified field tracks which user-editable fields in the entry have been changed since the last commit.
    modified []string

    // The read field contains the encrypted JSON string identifying the read access grants to the entry.
    read string
    // The write field contains the encrypted JSON string identifying the write access grants to the entry.
    write string
    // The delegate field contains the encrypted JSON string identifying the delegation access grants to the entry.
    delegate string

    // The group field is the encrypted name of the group to which the entry belongs.
    group string
    // The icon filed is the encrypted image data of the entry.
    icon string
    // The title field is the encrypted title of the entry.
    title string

    // The username field is the encrypted username stored in the entry.
    username string
    // The password field is the encrypted password stored in the entry.
    password string
    // The url field is the encrypted url stored in the entry.
    url string
    // The comment field is the encrypted comment stored in the entry.
    comment string
    // The expiry field is the encrypted expiry date of the password stored in the entry.
    expiry string
    // The extras field is extra encrypted JSON data associated with the entry.
    extras string

    // The userdata field is extra encrypted user-specific JSON data associated with the entry.
    userdata string

    // Mutex to synchronize read/write access to fields.
    mutex sync.RWMutex
}

// The decryptGrants function decrypts an encrypted JSON grants string and populates the provided list with Grant objects based on the resulting JSON.
// The entry mutex must be locked for reading prior to calling this method.
func decryptGrants(encryptedGrants string, key []byte) ([]Grant, error) {
    data, err = Decrypt(encryptedGrants, key)
    if err != nil {
        return nil, err
    }

    var grantJson interface{}
    err := json.Unmarshal(data, &grantJson)
    if err != nil {
        return nil, err
    }

    var grants []Grant
    for _, g := range grantJson.([]interface{}) {
        item = g.(map[string]interface{})
        append(grants, NewPreSignedGrant(item["user"].(string), item["signer"].(string), item["signature"].(string)))
    }
    return grants, nil
}

// The canRead function determines if the given user has read access to the entry.  This function may decrypt the read grants field.
// The entry mutex must be locked for reading prior to calling this method.
func (e *Entry) canRead(user string, key []byte) bool {
    grants, err := decryptGrants(e.read, key)
    if err != nil {
        return false
    }

    for _, g := range grants {
        if g.For(user) {
            return g.Verify()
        }
    }
    return true
}

// The canWrite function determines if the given user has write access to the entry.  This function may decrypt the write grants field.
// The entry mutex must be locked for reading prior to calling this method.
func (e *Entry) canWrite(user string, key []byte) bool {
    grants, err := decryptGrants(e.write, key)
    if err != nil {
        return false
    }

    for _, g := range grants {
        if g.For(user) {
            return g.Verify()
        }
    }
    return true
}

// The canDelegate function determines if the given user has delegation permissions on the entry.
// The entry mutex must be locked for reading prior to calling this method.
func (e *Entry) canDelegate(user string, key []byte) bool {
    grants, err := decryptGrants(e.delegate, key)
    if err != nil {
        return false
    }

    for _, g := range grants {
        if g.For(user) {
            return g.Verify()
        }
    }
    return true
}

// ReadGroup reads the group field of the entry, provided that the user has appropriate permissions and a valid decryption key.
// Read access to the group field is granted to users with read, write, or delegation permission, since this field is necessary
// in order to be able to display the entry properly.
func (e *Entry) ReadGroup(user string, key []byte) (string, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) || e.canWrite(user) || e.canDelegate(user) {
        data, err = Decrypt(e.group, key)
        if err != nil {
            return nil, err
        }
        return string(data), nil
    }
    return nil, &Error{ErrPermission, "group read permission denied"}
}

// ReadIcon reads the icon field of the entry, provided that the user has appropriate permissions and a valid decryption key.
// Read access to the icon field is granted to users with read, write, or delegation permission, since this field is necessary
// in order to be able to display the entry properly.
func (e *Entry) ReadIcon(user string, key []byte) (image.Image, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) || e.canWrite(user) || e.canDelegate(user) {
        data, err = Decrypt(e.icon, key)
        if err != nil {
            return nil, err
        }

        r = bytes.NewReader(data)
        img, _, err = png.Decode(r)
        if err != nil {
            return nil, err
        }
        return img, nil
    }
    return nil, &Error{ErrPermission, "icon read permission denied"}
}

// ReadTitle reads the title field of the entry, provided that the user has appropriate permissions and a valid decryption key.
// Read access to the title field is granted to users with read, write, or delegation permission, since this field is necessary
// in order to be able to display the entry properly.
func (e *Entry) ReadTitle(user string, key []byte) (string, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) || e.canWrite(user) || e.canDelegate(user) {
        data, err = Decrypt(e.title, key)
        if err != nil {
            return nil, err
        }
        return string(data), nil
    }
    return nil, &Error{ErrPermission, "title read permission denied"}
}

// ReadUsername reads the username field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (e *Entry) ReadUsername(user string, key []byte) (string, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) {
        data, err = Decrypt(e.username, key)
        if err != nil {
            return nil, err
        }
        return string(data), nil
    }
    return nil, &Error{ErrPermission, "username read permission denied"}
}

// ReadPassword reads the password field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (e *Entry) ReadPassword(user string, key []byte) (string, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) {
        data, err = Decrypt(e.password, key)
        if err != nil {
            return nil, err
        }
        return string(data), nil
    }
    return nil, &Error{ErrPermission, "password read permission denied"}
}

// ReadUrl reads the password field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (e *Entry) ReadUrl(user string, key []byte) (string, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) {
        data, err = Decrypt(e.url, key)
        if err != nil {
            return nil, err
        }
        return string(data), nil
    }
    return nil, &Error{ErrPermission, "URL read permission denied"}
}

// ReadComment reads the comment field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (e *Entry) ReadComment(user string, key []byte) (string, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) {
        data, err = Decrypt(e.comment, key)
        if err != nil {
            return nil, err
        }
        return string(data), nil
    }
    return nil, &Error{ErrPermission, "comment read permission denied"}
}

// ReadExpiry reads the expiry date field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (e *Entry) ReadExpiry(user string, key []byte) (time.Time, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) {
        data, err = Decrypt(e.expiry, key)
        if err != nil {
            return nil, err
        }

        t, err = time.Parse(time.RFC3339, data.(string))
        if err != nil {
            return nil, err
        }
        return t, nil
    }
    return nil, &Error{ErrPermission, "expiry date read permission denied"}
}

// ReadExtras reads the extras field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (e *Entry) ReadExtras(user string, key []byte) (map[string]interface{}, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    if e.canRead(user) {
        data, err = Decrypt(e.extras, key)
        if err != nil {
            return nil, err
        }

        var extras interface{}
        err := json.Unmarshal(data, &extras)
        if err != nil {
            return nil, err
        }
        return extras, nil
    }
    return nil, &Error{ErrPermission, "comment read permission denied"}
}

// ReadUserdata reads the userdata field of the entry, provided that the user has a valid decryption key.
// No specific permissions are required since this field is only ever accesible by the user and is not propagated to others.
func (e *Entry) ReadUserdata(user string, key []byte) (map[string]interface{}, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    data, err = Decrypt(e.userdata, key)
    if err != nil {
        return nil, err
    }

    var userdata interface{}
    err := json.Unmarshal(data, &userdata)
    if err != nil {
        return nil, err
    }
    return userdata, nil
}

// WriteGroup writes the group field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteGroup(user string, key []byte, group string) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(name), key)
        if err != nil {
            return err
        }
        e.group = data
        if !Contains(e.modified, "group") {
            append(e.modified, "group")
        }
        return nil
    }
    return &Error{ErrPermission, "group write permission denied"}
}

// WriteIcon writes the icon field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteIcon(user string, key []byte, icon image.Image) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        var w bytes.Buffer
        err = png.Encode(w, icon)
        if err != nil {
            return err
        }

        data, err = Encrypt(w.Bytes(), key)
        if err != nil {
            return err
        }
        e.icon = data
        if !Contains(e.modified, "icon") {
            append(e.modified, "icon")
        }
        return nil
    }
    return &Error{ErrPermission, "icon write permission denied"}
}

// WriteTitle writes the title field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteTitle(user string, key []byte, title string) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(title), key)
        if err != nil {
            return err
        }
        e.title = data
        if !Contains(e.modified, "title") {
            append(e.modified, "title")
        }
        return nil
    }
    return &Error{ErrPermission, "title write permission denied"}
}

// WriteUsername writes the username field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteUsername(user string, key []byte, username string) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(username), key)
        if err != nil {
            return err
        }
        e.username = data
        if !Contains(e.modified, "username") {
            append(e.modified, "username")
        }
        return nil
    }
    return &Error{ErrPermission, "username write permission denied"}
}

// WritePassword writes the password field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WritePassword(user string, key []byte, password string) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(password), key)
        if err != nil {
            return err
        }
        e.password = data
        if !Contains(e.modified, "password") {
            append(e.modified, "password")
        }
        return nil
    }
    return &Error{ErrPermission, "password write permission denied"}
}

// WriteUrl writes the url field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteUrl(user string, key []byte, url string) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(url), key)
        if err != nil {
            return err
        }
        e.url = data
        if !Contains(e.modified, "url") {
            append(e.modified, "url")
        }
        return nil
    }
    return &Error{ErrPermission, "url write permission denied"}
}

// WriteComment writes the comment field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteComment(user string, key []byte, comment string) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(comment), key)
        if err != nil {
            return err
        }
        e.comment = data
        if !Contains(e.modified, "comment") {
            append(e.modified, "comment")
        }
        return nil
    }
    return &Error{ErrPermission, "comment write permission denied"}
}

// WriteExpiry writes the expiry field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteExpiry(user string, key []byte, expiry time.Time) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        data, err = Encrypt([]byte(expiry.Format(time.RFC3339)), key)
        if err != nil {
            return err
        }
        e.expiry = data
        if !Contains(e.modified, "expiry") {
            append(e.modified, "expiry")
        }
        return nil
    }
    return &Error{ErrPermission, "expiry date write permission denied"}
}

// WriteExtras writes the extras field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (e *Entry) WriteExtras(user string, key []byte, extras interface{}) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.canWrite(user) {
        bytes, err := json.Marshal(extras)
        if err != nil {
            return err
        }

        data, err = Encrypt(bytes, key)
        if err != nil {
            return err
        }
        e.extras = data
        if !Contains(e.modified, "extras") {
            append(e.modified, "extras")
        }
        return nil
    }
    return &Error{ErrPermission, "extras write permission denied"}
}

// WriteUserdata writes the userdata field of the entry, provided that the user a valid encryption key.
func (e *Entry) WriteUserdata(user string, key []byte, userdata interface{}) error {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    bytes, err := json.Marshal(userdata)
    if err != nil {
        return err
    }

    data, err = Encrypt(bytes, key)
    if err != nil {
        return err
    }
    e.userdata = data
    if !Contains(e.modified, "userdata") {
        append(e.modified, "userdata")
    }
    return nil
}
