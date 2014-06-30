// Package utils provides small generic helper functions for use in PassRep.
package utils

import (
    "crypto/rand"
)

// Contains determines if the given string is contained in the slice of strings.
func Contains(slice []string, value string) bool {
    for _, v := range slice {
        if v == value {
            return true
        }
    }
    return false
}

// AppendUnique only appends the string item if it is not already in the slice of strings.
func AppendUnique(slice []string, value string) []string {
    if !Contains(slice, value) {
        return append(slice, value)
    }
    return slice
}

// RandomBytes produces a buffer of specified length containing cryptographically secure pseudorandom data.
func RandomBytes(size int) []byte {
    result := make([]byte, size)
    _, err := rand.Read(result)
    if err != nil {
        result = nil
    }
    return result
}
