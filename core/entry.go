package core

import (
    "encoding/json"
    "time"
)

// EntryView instances represent one user's view of a password database entry.
// Most fields are kept encrypted until they need to be accessed.
type EntryView struct {
    // The Id is the database row identifier.
    Id  int64
    // CreatedAt is the time when the entry was created.
    CreatedAt time.Time
    // UpdatedAt is the time when the entry was last updated.
    UpdatedAt time.Time

    // The EntryId string is the unique identifier for the password entry, and ties together the individual views into the entry of each user.
    EntryId string

    // UserId is the foreign key of the owning user's database entry.
    UserId int64

    // The Permissions field is the signed string describing the permissions that the user has for this entry.  The permissions are granted
    // by the associated authority.
    Permissions string
    // AuthorityId is the foreign key of the user granting the permissions for this entry.
    AuthorityId int64

    // The Group field is the encrypted name of the group to which the entry belongs.
    Group string
    // The Icon field is the encrypted image data or path to image file of the entry.
    Icon string
    // The Title field is the encrypted title of the entry.
    Title string

    // The Username field is the encrypted username stored in the entry.
    Username string
    // The Password field is the encrypted password stored in the entry.
    Password string
    // The Url field is the encrypted url stored in the entry.
    Url string
    // The Comment field is the encrypted comment stored in the entry.
    Comment string
    // The Expiry field is the encrypted expiry date of the password stored in the entry.
    Expiry string
    // The Extras field is extra encrypted JSON data associated with the entry.
    Extras string

    // The Userdata field is extra encrypted user-specific JSON data associated with the entry.
    Userdata string
}

// The getAuthority function finds the authority user model instance and sets the internal reference pointer.
func (this *EntryView) getAuthority() *User {
    authority := new(User)
    DB.Model(this).Related(authority, "AuthorityId")
    return authority
}

// The getUser function finds the user model instance and sets the internal reference pointer.
func (this *EntryView) getUser() *User {
    user := new(User)
    DB.Model(this).Related(user, "UserId")
    return user
}

// ReadGroup reads the group field of the entry, provided that the user has appropriate permissions.
// Read access to the group field is granted to users with any permissions, since this field is necessary in order to be able
// to display the entry properly.
func (this *EntryView) ReadGroup() (string, error) {
    if this.getUser().Can("*", this) {
        data, err := this.getUser().Decrypt(this.Group)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
    return "", NewError("Group read permission denied", this.getUser())
}

// ReadIcon reads the icon field of the entry, provided that the user has appropriate permissions.
// Read access to the icon field is granted to users with any permissions, since this field is necessary
// in order to be able to display the entry properly.
func (this *EntryView) ReadIcon() (string, error) {
    if this.getUser().Can("*", this) {
        data, err := this.getUser().Decrypt(this.Icon)
        if err != nil {
            return "", err
        }

        return string(data), nil
    }
    return "", NewError("Icon read permission denied", this.getUser())
}

// ReadTitle reads the title field of the entry, provided that the user has appropriate permissions.
// Read access to the title field is granted to users with any permissions, since this field is necessary
// in order to be able to display the entry properly.
func (this *EntryView) ReadTitle() (string, error) {
    if this.getUser().Can("*", this) {
        data, err := this.getUser().Decrypt(this.Title)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
    return "", NewError("Title read permission denied", this.getUser())
}

// ReadUsername reads the username field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) ReadUsername() (string, error) {
    if this.getUser().Can("r", this) {
        data, err := this.getUser().Decrypt(this.Username)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
    return "", NewError("Username read permission denied", this.getUser())
}

// ReadPassword reads the password field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) ReadPassword() (string, error) {
    if this.getUser().Can("r", this) {
        data, err := this.getUser().Decrypt(this.Password)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
    return "", NewError("Password read permission denied", this.getUser())
}

// ReadUrl reads the password field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) ReadUrl() (string, error) {
    if this.getUser().Can("r", this) {
        data, err := this.getUser().Decrypt(this.Url)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
    return "", NewError("URL read permission denied", this.getUser())
}

// ReadComment reads the comment field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) ReadComment() (string, error) {
    if this.getUser().Can("r", this) {
        data, err := this.getUser().Decrypt(this.Comment)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
    return "", NewError("Comment read permission denied", this.getUser())
}

// ReadExpiry reads the expiry date field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) ReadExpiry() (time.Time, error) {
    if this.getUser().Can("r", this) {
        data, err := this.getUser().Decrypt(this.Expiry)
        if err != nil {
            return time.Now(), err
        }

        var t time.Time
        err = t.UnmarshalText(data)
        if err != nil {
            return time.Now(), NewError(err, this.getUser())
        }
        return t, nil
    }
    return time.Now(), NewError("Expiry date read permission denied", this.getUser())
}

// ReadExtras reads the extras field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) ReadExtras(user string) (interface{}, error) {
    if this.getUser().Can("r", this) {
        data, err := this.getUser().Decrypt(this.Extras)
        if err != nil {
            return nil, err
        }

        var extras interface{}
        err = json.Unmarshal(data, &extras)
        if err != nil {
            return nil, NewError(err, this.getUser())
        }
        return extras, nil
    }
    return nil, NewError("Comment read permission denied", this.getUser())
}

// ReadUserdata reads the userdata field of the entry.
// No specific permissions are required since this field is only ever accessible by the user and is not propagated to others.
func (this *EntryView) ReadUserdata() (interface{}, error) {
    data, err := this.getUser().Decrypt(this.Userdata)
    if err != nil {
        return nil, err
    }

    var userdata interface{}
    err = json.Unmarshal(data, &userdata)
    if err != nil {
        return nil, NewError(err, this.getUser())
    }
    return userdata.(map[string]interface{}), nil
}

// WriteGroup writes the group field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteGroup(group string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(group))
        if err != nil {
            return err
        }
        this.Group = data
        return nil
    }
    return NewError("Group write permission denied", this.getUser())
}

// WriteIcon writes the icon field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteIcon(icon string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(icon))
        if err != nil {
            return err
        }
        this.Icon = data
        return nil
    }
    return NewError("Icon write permission denied", this.getUser())
}

// WriteTitle writes the title field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteTitle(title string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(title))
        if err != nil {
            return err
        }
        this.Title = data
        return nil
    }
    return NewError("Title write permission denied", this.getUser())
}

// WriteUsername writes the username field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteUsername(username string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(username))
        if err != nil {
            return err
        }
        this.Username = data
        return nil
    }
    return NewError("Username write permission denied", this.getUser())
}

// WritePassword writes the password field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WritePassword(password string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(password))
        if err != nil {
            return err
        }
        this.Password = data
        return nil
    }
    return NewError("Password write permission denied", this.getUser())
}

// WriteUrl writes the url field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteUrl(url string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(url))
        if err != nil {
            return err
        }
        this.Url = data
        return nil
    }
    return NewError("URL write permission denied", this.getUser())
}

// WriteComment writes the comment field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteComment(comment string) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(comment))
        if err != nil {
            return err
        }
        this.Comment = data
        return nil
    }
    return NewError("Comment write permission denied", this.getUser())
}

// WriteExpiry writes the expiry field of the entry, provided that the user has appropriate permissions.
func (this *EntryView) WriteExpiry(expiry time.Time) error {
    if this.getUser().Can("w", this) {
        data, err := this.getUser().Encrypt([]byte(expiry.Format(time.RFC3339)))
        if err != nil {
            return err
        }
        this.Expiry = data
        return nil
    }
    return NewError("Expiry date write permission denied", this.getUser())
}

// WriteExtras writes the extras field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *EntryView) WriteExtras(extras interface{}) error {
    if this.getUser().Can("w", this) {
        bytes, err := json.Marshal(extras)
        if err != nil {
            return NewError(err, this.getUser())
        }

        data, e := this.getUser().Encrypt(bytes)
        if e != nil {
            return e
        }
        this.Extras = data
        return nil
    }
    return NewError("Extras write permission denied", this.getUser())
}

// WriteUserdata writes the userdata field of the entry, provided that the user a valid encryption key.
func (this *EntryView) WriteUserdata(userdata interface{}) error {
    bytes, err := json.Marshal(userdata)
    if err != nil {
        return NewError(err, this.getUser())
    }

    data, e := this.getUser().Encrypt(bytes)
    if e != nil {
        return e
    }
    this.Userdata = data
    return nil
}
