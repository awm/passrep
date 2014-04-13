package core

import (
    "bytes"
    "encoding/json"
    "github.com/awm/passrep/utils"
    "image"
    "image/png"
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

// The canDo function determines if the provided encrypted grants string authorizes the user to perform some arbitrary action which
// is determined by the calling context.  The entry mutex must be locked for reading prior to calling this method.
func (this *Entry) canDo(encryptedGrants string, user string, key []byte) bool {
    data, err := Decrypt(encryptedGrants, key)
    if err != nil {
        return false
    }

    var grants []Grant
    e := json.Unmarshal(data, &grants)
    if e != nil {
        return false
    }

    for _, g := range grants {
        if g.For(this.id, user) {
            return true
        }
    }
    return false
}

// The canRead function determines if the given user has read access to the entry.
// The entry mutex must be locked for reading prior to calling this method.
func (this *Entry) canRead(user string, key []byte) bool {
    return this.canDo(this.read, user, key)
}

// The canWrite function determines if the given user has write access to the entry.
// The entry mutex must be locked for reading prior to calling this method.
func (this *Entry) canWrite(user string, key []byte) bool {
    return this.canDo(this.write, user, key)
}

// The canDelegate function determines if the given user has delegation permissions on the entry.
// The entry mutex must be locked for reading prior to calling this method.
func (this *Entry) canDelegate(user string, key []byte) bool {
    return this.canDo(this.delegate, user, key)
}

// ReadGroup reads the group field of the entry, provided that the user has appropriate permissions and a valid decryption key.
// Read access to the group field is granted to users with read, write, or delegation permission, since this field is necessary
// in order to be able to display the entry properly.
func (this *Entry) ReadGroup(user string, key []byte) (string, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) || this.canWrite(user, key) || this.canDelegate(user, key) {
        data, err := Decrypt(this.group, key)
        if err != nil {
            return "", err.SetUser(user)
        }
        return string(data), nil
    }
    return "", &Error{ErrPermission, user, "group read permission denied"}
}

// ReadIcon reads the icon field of the entry, provided that the user has appropriate permissions and a valid decryption key.
// Read access to the icon field is granted to users with read, write, or delegation permission, since this field is necessary
// in order to be able to display the entry properly.
func (this *Entry) ReadIcon(user string, key []byte) (image.Image, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) || this.canWrite(user, key) || this.canDelegate(user, key) {
        data, err := Decrypt(this.icon, key)
        if err != nil {
            return nil, err.SetUser(user)
        }

        r := bytes.NewReader(data)
        img, e := png.Decode(r)
        if e != nil {
            return nil, &Error{ErrOther, user, e.Error()}
        }
        return img, nil
    }
    return nil, &Error{ErrPermission, user, "icon read permission denied"}
}

// ReadTitle reads the title field of the entry, provided that the user has appropriate permissions and a valid decryption key.
// Read access to the title field is granted to users with read, write, or delegation permission, since this field is necessary
// in order to be able to display the entry properly.
func (this *Entry) ReadTitle(user string, key []byte) (string, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) || this.canWrite(user, key) || this.canDelegate(user, key) {
        data, err := Decrypt(this.title, key)
        if err != nil {
            return "", err.SetUser(user)
        }
        return string(data), nil
    }
    return "", &Error{ErrPermission, user, "title read permission denied"}
}

// ReadUsername reads the username field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (this *Entry) ReadUsername(user string, key []byte) (string, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) {
        data, err := Decrypt(this.username, key)
        if err != nil {
            return "", err.SetUser(user)
        }
        return string(data), nil
    }
    return "", &Error{ErrPermission, user, "username read permission denied"}
}

// ReadPassword reads the password field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (this *Entry) ReadPassword(user string, key []byte) (string, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) {
        data, err := Decrypt(this.password, key)
        if err != nil {
            return "", err.SetUser(user)
        }
        return string(data), nil
    }
    return "", &Error{ErrPermission, user, "password read permission denied"}
}

// ReadUrl reads the password field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (this *Entry) ReadUrl(user string, key []byte) (string, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) {
        data, err := Decrypt(this.url, key)
        if err != nil {
            return "", err.SetUser(user)
        }
        return string(data), nil
    }
    return "", &Error{ErrPermission, user, "URL read permission denied"}
}

// ReadComment reads the comment field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (this *Entry) ReadComment(user string, key []byte) (string, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) {
        data, err := Decrypt(this.comment, key)
        if err != nil {
            return "", err.SetUser(user)
        }
        return string(data), nil
    }
    return "", &Error{ErrPermission, user, "comment read permission denied"}
}

// ReadExpiry reads the expiry date field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (this *Entry) ReadExpiry(user string, key []byte) (time.Time, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) {
        data, err := Decrypt(this.expiry, key)
        if err != nil {
            return time.Now(), err.SetUser(user)
        }

        var t time.Time
        e := t.UnmarshalText(data)
        if e != nil {
            return time.Now(), &Error{ErrOther, user, e.Error()}
        }
        return t, nil
    }
    return time.Now(), &Error{ErrPermission, user, "expiry date read permission denied"}
}

// ReadExtras reads the extras field of the entry, provided that the user has appropriate permissions and a valid decryption key.
func (this *Entry) ReadExtras(user string, key []byte) (map[string]interface{}, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    if this.canRead(user, key) {
        data, err := Decrypt(this.extras, key)
        if err != nil {
            return nil, err.SetUser(user)
        }

        var extras interface{}
        e := json.Unmarshal(data, &extras)
        if e != nil {
            return nil, &Error{ErrOther, user, e.Error()}
        }
        return extras.(map[string]interface{}), nil
    }
    return nil, &Error{ErrPermission, user, "comment read permission denied"}
}

// ReadUserdata reads the userdata field of the entry, provided that the user has a valid decryption key.
// No specific permissions are required since this field is only ever accesible by the user and is not propagated to others.
func (this *Entry) ReadUserdata(user string, key []byte) (map[string]interface{}, error) {
    this.mutex.RLock()
    defer this.mutex.RUnlock()

    data, err := Decrypt(this.userdata, key)
    if err != nil {
        return nil, err.SetUser(user)
    }

    var userdata interface{}
    e := json.Unmarshal(data, &userdata)
    if e != nil {
        return nil, &Error{ErrOther, user, e.Error()}
    }
    return userdata.(map[string]interface{}), nil
}

// WriteGroup writes the group field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteGroup(user string, key []byte, group string) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(group), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.group = data
        this.modified = utils.AppendUnique(this.modified, "group")
        return nil
    }
    return &Error{ErrPermission, user, "group write permission denied"}
}

// WriteIcon writes the icon field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteIcon(user string, key []byte, icon image.Image) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        var w bytes.Buffer
        e := png.Encode(&w, icon)
        if e != nil {
            return &Error{ErrOther, user, e.Error()}
        }

        data, err := Encrypt(w.Bytes(), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.icon = data
        this.modified = utils.AppendUnique(this.modified, "icon")
        return nil
    }
    return &Error{ErrPermission, user, "icon write permission denied"}
}

// WriteTitle writes the title field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteTitle(user string, key []byte, title string) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(title), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.title = data
        this.modified = utils.AppendUnique(this.modified, "title")
        return nil
    }
    return &Error{ErrPermission, user, "title write permission denied"}
}

// WriteUsername writes the username field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteUsername(user string, key []byte, username string) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(username), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.username = data
        this.modified = utils.AppendUnique(this.modified, "username")
        return nil
    }
    return &Error{ErrPermission, user, "username write permission denied"}
}

// WritePassword writes the password field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WritePassword(user string, key []byte, password string) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(password), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.password = data
        this.modified = utils.AppendUnique(this.modified, "password")
        return nil
    }
    return &Error{ErrPermission, user, "password write permission denied"}
}

// WriteUrl writes the url field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteUrl(user string, key []byte, url string) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(url), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.url = data
        this.modified = utils.AppendUnique(this.modified, "url")
        return nil
    }
    return &Error{ErrPermission, user, "url write permission denied"}
}

// WriteComment writes the comment field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteComment(user string, key []byte, comment string) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(comment), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.comment = data
        this.modified = utils.AppendUnique(this.modified, "comment")
        return nil
    }
    return &Error{ErrPermission, user, "comment write permission denied"}
}

// WriteExpiry writes the expiry field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteExpiry(user string, key []byte, expiry time.Time) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        data, err := Encrypt([]byte(expiry.Format(time.RFC3339)), key)
        if err != nil {
            return err.SetUser(user)
        }
        this.expiry = data
        this.modified = utils.AppendUnique(this.modified, "expiry")
        return nil
    }
    return &Error{ErrPermission, user, "expiry date write permission denied"}
}

// WriteExtras writes the extras field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *Entry) WriteExtras(user string, key []byte, extras interface{}) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    if this.canWrite(user, key) {
        bytes, e := json.Marshal(extras)
        if e != nil {
            return &Error{ErrOther, user, e.Error()}
        }

        data, err := Encrypt(bytes, key)
        if err != nil {
            return err.SetUser(user)
        }
        this.extras = data
        this.modified = utils.AppendUnique(this.modified, "extras")
        return nil
    }
    return &Error{ErrPermission, user, "extras write permission denied"}
}

// WriteUserdata writes the userdata field of the entry, provided that the user a valid encryption key.
func (this *Entry) WriteUserdata(user string, key []byte, userdata interface{}) error {
    this.mutex.Lock()
    defer this.mutex.Unlock()

    bytes, e := json.Marshal(userdata)
    if e != nil {
        return &Error{ErrOther, user, e.Error()}
    }

    data, err := Encrypt(bytes, key)
    if err != nil {
        return err.SetUser(user)
    }
    this.userdata = data
    this.modified = utils.AppendUnique(this.modified, "userdata")
    return nil
}
