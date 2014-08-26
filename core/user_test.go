package core

import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    "testing"
)

type UserTestSuite struct {
    suite.Suite
}

func (suite *UserTestSuite) TestCreation() {
    u, err := NewUser("test.user", "password")
    if assert.NoError(suite.T(), err) {
        assert.Equal(suite.T(), u.Name, "test.user")
        assert.NotEmpty(suite.T(), u.CryptoSalt)
        assert.NotEmpty(suite.T(), u.SigningSalt)
        assert.NotEmpty(suite.T(), u.PublicKey)
        assert.NotNil(suite.T(), u.keys)
    }
}

func TestUserTestSuite(t *testing.T) {
    suite.Run(t, new(UserTestSuite))
}
