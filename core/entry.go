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
    // The user field is the pointer to the owning user's object.
    user *User

    // The Permissions field is the encrypted string describing the permissions that the user has for this entry.  The permissions are granted
    // by the associated authority.
    Permissions string
    // AuthorityId is the foreign key of the user granting the permissions for this entry.
    AuthorityId int64
    // The authority field is the pointer to the authorizing user's object.
    authority *User

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
    if this.authority == nil {
        var authority User
        DB.Model(this).Related(&authority, "AuthorityId")
        this.authority = &authority
    }
    return this.authority
}

// The getUser function finds the user model instance and sets the internal reference pointer.
func (this *EntryView) getUser() *User {
    if this.user == nil {
        var user User
        DB.Model(this).Related(&user, "UserId")
        this.user = &user
    }
    return this.user
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
    return "", &Error{ErrPermission, this.user.Name, "group read permission denied"}
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
    return "", &Error{ErrPermission, this.user.Name, "icon read permission denied"}
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
    return "", &Error{ErrPermission, this.user.Name, "title read permission denied"}
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
    return "", &Error{ErrPermission, this.user.Name, "username read permission denied"}
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
    return "", &Error{ErrPermission, this.user.Name, "password read permission denied"}
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
    return "", &Error{ErrPermission, this.user.Name, "URL read permission denied"}
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
    return "", &Error{ErrPermission, this.user.Name, "comment read permission denied"}
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
            return time.Now(), WrapError(err).SetCode(ErrOther).SetUser(this.user)
        }
        return t, nil
    }
    return time.Now(), &Error{ErrPermission, this.user.Name, "expiry date read permission denied"}
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
            return nil, WrapError(err).SetCode(ErrOther).SetUser(this.user)
        }
        return extras, nil
    }
    return nil, &Error{ErrPermission, this.user.Name, "comment read permission denied"}
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
        return nil, WrapError(err).SetCode(ErrOther).SetUser(this.user)
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
    return &Error{ErrPermission, this.user.Name, "group write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "icon write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "title write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "username write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "password write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "url write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "comment write permission denied"}
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
    return &Error{ErrPermission, this.user.Name, "expiry date write permission denied"}
}

// WriteExtras writes the extras field of the entry, provided that the user has appropriate permissions and a valid encryption key.
func (this *EntryView) WriteExtras(extras interface{}) error {
    if this.getUser().Can("w", this) {
        bytes, err := json.Marshal(extras)
        if err != nil {
            return WrapError(err).SetCode(ErrOther).SetUser(this.user)
        }

        data, e := this.getUser().Encrypt(bytes)
        if e != nil {
            return e
        }
        this.Extras = data
        return nil
    }
    return &Error{ErrPermission, this.user.Name, "extras write permission denied"}
}

// WriteUserdata writes the userdata field of the entry, provided that the user a valid encryption key.
func (this *EntryView) WriteUserdata(userdata interface{}) error {
    bytes, err := json.Marshal(userdata)
    if err != nil {
        return WrapError(err).SetCode(ErrOther).SetUser(this.user)
    }

    data, e := this.getUser().Encrypt(bytes)
    if e != nil {
        return e
    }
    this.Userdata = data
    return nil
}
