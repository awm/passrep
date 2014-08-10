package core

import (
    "fmt"
    "runtime"
)

// The Error type is the basic PWS error type used when no other type is more appropriate.
type Error struct {
    // The File is the source file where the error originated.
    File string
    // The Line is the source line where the error originated.
    Line int
    // The User is the name of the user for whom the error was generated.
    User string
    // The Msg is the string describing the error.
    Msg string
}

// NewError produces a new Error instance.
func NewError(content interface{}, user ...interface{}) *Error {
    err := new(Error)
    if user != nil {
        err.SetUser(user[0])
    }

    switch c := content.(type) {
    case error:
        err.Msg = c.Error()
    case string:
        err.Msg = c
    }

    _, file, line, ok := runtime.Caller(1)
    if ok {
        err.File = file
        err.Line = line
    }

    return err
}

// Error produces a string describing the error from the code and message.
func (this *Error) Error() string {
    result := ""
    if len(this.File) > 0 {
        result += fmt.Sprintf("%s:%d", this.File, this.Line)
    }
    if len(this.User) > 0 {
        if len(result) > 0 {
            result += " - "
        }
        result += this.User
    }
    if len(result) > 0 {
        result += ": "
    }
    result += this.Msg
    return result
}

// SetUser changes the user field after creation.
func (this *Error) SetUser(user interface{}) *Error {
    switch u := user.(type) {
    case *User:
        this.User = u.Name
    case string:
        this.User = u
    }
    return this
}
