package utils

import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    "testing"
)

type UtilsTestSuite struct {
    suite.Suite
}

func (suite *UtilsTestSuite) TestContains() {
    a := assert.New(suite.T())

    alpha := []string{"this", "is", "a", "test"}
    a.True(Contains(alpha, "is"), "Could not find word in slice")
    a.False(Contains(alpha, "isn't"), "Found word in slice that is not there")
}

func (suite *UtilsTestSuite) TestAppendUnique() {
    a := assert.New(suite.T())

    alpha := []string{"this", "is", "a", "test"}
    beta := AppendUnique(alpha, "right?")
    a.Equal(len(beta), len(alpha)+1, "Length did not increase")
    a.Equal(beta[len(beta)-1], "right?", "Last item did not match expectations")

    gamma := AppendUnique(beta, "test")
    a.Equal(len(gamma), len(beta), "Length increased")
    a.Equal(beta[len(beta)-1], "right?", "Last item did not match expectations")
}

func (suite *UtilsTestSuite) TestRandomBytes() {
    a := assert.New(suite.T())

    alpha := make([]byte, 32)
    beta := RandomBytes(32)
    a.False(assert.ObjectsAreEqual(alpha, beta), "Expected random data to not equal zeroed data")

    gamma := RandomBytes(32)
    a.False(assert.ObjectsAreEqual(alpha, gamma), "Expected more random data to not equal zeroed data")
    a.False(assert.ObjectsAreEqual(beta, gamma), "Expected one random data set to not equal another")
}

func TestUtilsTestSuite(t *testing.T) {
    suite.Run(t, new(UtilsTestSuite))
}
