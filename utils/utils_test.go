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
    alpha := []string{"this", "is", "a", "test"}
    assert.True(suite.T(), Contains(alpha, "is"), "Could not find word in slice")
    assert.False(suite.T(), Contains(alpha, "isn't"), "Found word in slice that is not there")
}

func (suite *UtilsTestSuite) TestAppendUnique() {
    alpha := []string{"this", "is", "a", "test"}
    beta := AppendUnique(alpha, "right?")
    assert.Equal(suite.T(), len(beta), len(alpha)+1, "Length did not increase")
    assert.Equal(suite.T(), beta[len(beta)-1], "right?", "Last item did not match expectations")

    gamma := AppendUnique(beta, "test")
    assert.Equal(suite.T(), len(gamma), len(beta), "Length increased")
    assert.Equal(suite.T(), beta[len(beta)-1], "right?", "Last item did not match expectations")
}

func (suite *UtilsTestSuite) TestRandomBytes() {
    alpha := make([]byte, 32)
    beta := RandomBytes(32)
    assert.False(suite.T(), assert.ObjectsAreEqual(alpha, beta), "Expected random data to not equal zeroed data")

    gamma := RandomBytes(32)
    assert.False(suite.T(), assert.ObjectsAreEqual(alpha, gamma), "Expected more random data to not equal zeroed data")
    assert.False(suite.T(), assert.ObjectsAreEqual(beta, gamma), "Expected one random data set to not equal another")
}

func TestUtilsTestSuite(t *testing.T) {
    suite.Run(t, new(UtilsTestSuite))
}
