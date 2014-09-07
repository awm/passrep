# PassRep #

*A multi-user password repository.*

[![Build Status](https://travis-ci.org/awm/passrep.svg?branch=master)](https://travis-ci.org/awm/passrep)

## Introduction ##

The goal of this project is to produce a password storage application along the lines of [KeePass][] or [KeePassX][] which is both cross-platform and allows access control different users can have different permission levels on password entries.  One potential use case is a small corporate IT department where the primary IT staff have access to everything, but the sales and marketing department is delegated access to the credentials for the public website, etc. so that they can make updates to the content.

Currently development is focused on the core library of functionality, with the user interface to follow later.  **This project is still in a very early stage and should not be used for any purpose other than testing and development of the system itself.  In particular, it is quite likely that there are many security flaws present in the implementation.**  Constructive feedback or patches are always welcome.

[KeePass]:  http://keepass.info/        "KeePass Password Safe"
[KeePassX]: http://www.keepassx.org/    "Cross Platform Password Manager"

## Building / Testing ##

[Go][] must be installed in order to build the project.

Ensure that the repository is cloned into a [Go Workspace][] and that the GOPATH variable is set appropriately.  Using the go command in the workspace directory this might look like

```bash
go get github.com/awm/passrep
```

To install the necessary dependencies (the three periods are literal, not a placeholder):

```bash
go get -t ...
```

To run the tests:

```bash
go test github.com/awm/passrep/utils
go test github.com/awm/passrep/core
```

[Go]:           http://golang.org/              "The Go Programming Language"
[Go Workspace]: http://golang.org/doc/code.html "How to Write Go Code"
