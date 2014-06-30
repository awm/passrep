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
    e := &Error{Code: ErrOther, User: "test.user", Msg: "A test error"}
    assert.EqualError(suite.T(), e, "Other error for test.user: A test error", "Error did not match")
}

func (suite *ErrorTestSuite) TestWrapping() {
    u := User{Name: "test.user"}
    e := WrapError(assert.AnError).SetCode(ErrOther).SetUser(&u)
    assert.EqualError(suite.T(), e, "Other error for test.user: assert.AnError general error for testing", "Error did not match")
}

func TestErrorTestSuite(t *testing.T) {
    suite.Run(t, new(ErrorTestSuite))
}
