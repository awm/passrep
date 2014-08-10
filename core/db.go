package core

import (
    "fmt"
    "github.com/jinzhu/gorm"
    _ "github.com/mattn/go-sqlite3"
)

var DB gorm.DB

// most of this is temporary for testing and will be cleaned up later as the database handling is fleshed out
func init() {
    DB, err := gorm.Open("sqlite3", "/tmp/passwords.db")
    if err != nil {
        panic(fmt.Sprintf("Error when connecting to database: %v", err))
    }

    DB.LogMode(true)
    DB.CreateTable(User{})
}
