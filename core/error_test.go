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
    a := assert.New(suite.T())

    e := NewError("A test error", "test.user")
    a.Error(e)
    a.Contains(e.Error(), "error_test.go:19 - test.user: A test error")
}

func (suite *ErrorTestSuite) TestWrapping() {
    a := assert.New(suite.T())

    u := User{Name: "test.user"}
    e := NewError(assert.AnError, &u)
    a.Error(e)
    a.Contains(e.Error(), "error_test.go:28 - test.user: assert.AnError general error for testing")

    e = NewError(assert.AnError)
    a.Error(e)
    a.Contains(e.Error(), "error_test.go:32: assert.AnError general error for testing")

    e2 := NewError(e)
    a.Error(e2)
    a.Contains(e2.Error(), "error_test.go:36: assert.AnError general error for testing")
}

func TestErrorTestSuite(t *testing.T) {
    suite.Run(t, new(ErrorTestSuite))
}
