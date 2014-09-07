package core

import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    "testing"
    "time"
)

type UserTestSuite struct {
    suite.Suite
}

func (suite *UserTestSuite) TestCreation() {
    a := assert.New(suite.T())

    u, err := NewUser("test.user", "password")
    if a.NoError(err) {
        a.Equal(u.Name, "test.user")
        a.NotEmpty(u.CryptoSalt)
        a.NotEmpty(u.SigningSalt)
        a.NotEmpty(u.PublicKey)
        a.NotNil(u.keys)

        u.Drop()
    }
}

func (suite *UserTestSuite) TestLoading() {
    a := assert.New(suite.T())

    original, err := NewUser("test.user", "password")
    if a.NoError(err) {
        loaded, err := LoadUser("test.user")
        if a.NoError(err) {
            a.Equal(loaded.Id, original.Id)
            a.WithinDuration(loaded.CreatedAt, original.CreatedAt, 0*time.Second)
            a.WithinDuration(loaded.UpdatedAt, original.UpdatedAt, 0*time.Second)
            a.Equal(loaded.Name, original.Name)
            a.Equal(loaded.CryptoSalt, original.CryptoSalt)
            a.Equal(loaded.SigningSalt, original.SigningSalt)
            a.Equal(loaded.PublicKey, original.PublicKey)
            a.Nil(loaded.keys)
        }

        original.Drop()
        loaded, err = LoadUser("test.user")
        a.Error(err)
    }
}

func (suite *UserTestSuite) TestSaltAccess() {
    a := assert.New(suite.T())

    u, err := NewUser("test.user", "password")
    if a.NoError(err) {
        c, err := u.GetCryptoSalt()
        if a.NoError(err) {
            a.NotEmpty(c)

            s, err := u.GetSigningSalt()
            if a.NoError(err) {
                a.NotEmpty(s)
                a.NotEqual(c, s)
            }
        }

        u.Drop()
    }
}

// func (suite *UserTestSuite) TestCan() {
//     a := assert.New(suite.T())

//     authority, err := NewUser("admin", "secret")
//     if a.NoError(err) {
//         user, err := NewUser("test.user", "password")
//         if a.NoError(err) {

//             entry1 := Entry{AuthorityId: authority.Id, Permissions: "...rwd"}
//             entry2 := Entry{AuthorityId: authority.Id, Permissions: "...r"}
//             entry3 := Entry{AuthorityId: authority.Id, Permissions: "...$"}

//             a.True(user.Can("*", &entry1))
//             a.True(user.Can("r", &entry1))
//             a.True(user.Can("w", &entry1))
//             a.True(user.Can("d", &entry1))
//             a.True(user.Can("rw", &entry1))
//             a.True(user.Can("rd", &entry1))
//             a.True(user.Can("wd", &entry1))
//             a.True(user.Can("rwd", &entry1))
//             a.False(user.Can("$", &entry1))
//             a.False(user.Can("r?", &entry1))

//             a.True(user.Can("*", &entry2))
//             a.True(user.Can("r", &entry2))
//             a.False(user.Can("w", &entry2))
//             a.False(user.Can("d", &entry2))
//             a.True(user.Can("rw", &entry2))
//             a.True(user.Can("rd", &entry2))
//             a.False(user.Can("wd", &entry2))
//             a.True(user.Can("rwd", &entry2))
//             a.False(user.Can("$", &entry2))
//             a.False(user.Can("r?", &entry2))

//             a.False(user.Can("*", &entry3))

//             user.Drop()
//         }
//         authority.Drop()
//     }
// }

func TestUserTestSuite(t *testing.T) {
    suite.Run(t, new(UserTestSuite))
}
