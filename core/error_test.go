package core

import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    "testing"
)

// While the Error implementation is simple enough that extensive testing is probably not required,
// this was an opportunity to become more familiar with the testing infrastructure.

type ErrorTestSuite struct {
    suite.Suite
}

func (suite *ErrorTestSuite) TestCreation() {
    e := NewError("A test error", "test.user")
    assert.Error(suite.T(), e)
    assert.Contains(suite.T(), e.Error(), "error_test.go:17 - test.user: A test error")
}

func (suite *ErrorTestSuite) TestWrapping() {
    u := User{Name: "test.user"}
    e := NewError(assert.AnError, &u)
    assert.Error(suite.T(), e)
    assert.Contains(suite.T(), e.Error(), "error_test.go:24 - test.user: assert.AnError general error for testing")

    e = NewError(assert.AnError)
    assert.Error(suite.T(), e)
    assert.Contains(suite.T(), e.Error(), "error_test.go:28: assert.AnError general error for testing")
}

func TestErrorTestSuite(t *testing.T) {
    suite.Run(t, new(ErrorTestSuite))
}
