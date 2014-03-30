package core

import (
    "fmt"
)

// The ErrorCode type represents an enumerated error value.
type ErrorCode uint

const (
    // ErrOk indicates that there are no problems.
    ErrOk ErrorCode = iota
    // ErrPermission indicates that the user does not have permission to perform the requested action.
    ErrPermission
    // ErrDecryption indicates that a decryption operation failed.
    ErrDecryption
    // ErrEncryption indicates that an encryption operation failed.
    ErrEncryption
    // ErrOther indicates that an error occurred during a non-PassRep operation.
    ErrOther
)

// The codeDesc map associates error codes with a word decribing the error.
var codeDesc = map[ErrorCode]string{
    ErrOk:         "No",
    ErrPermission: "Permission",
    ErrDecryption: "Decryption",
    ErrEncryption: "Encryption",
    ErrOther:      "Other",
}

// The Error type is the basic PWS error type used when no other type is more appropriate.
type Error struct {
    // The Code is the numeric error value.
    Code ErrorCode
    // The User is the name of the user for whom the error was generated.
    User string
    // The Msg is the string describing the error.
    Msg string
}

// Error produces a string describing the error from the code and message.
func (e *Error) Error() string {
    return fmt.Sprintf("%s error for %s: %s", codeDesc[e.Code], e.User, e.Msg)
}

// SetUser changes the user field after creation.
func (e *Error) SetUser(user string) *Error {
    e.User = user
    return e
}
