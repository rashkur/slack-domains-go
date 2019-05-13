#!/bin/bash

t="/tmp/go-cover.$$.tmp"
go test -coverprofile=$t $@ && go tool cover -html=$t && unlink $t

#go test -cover -coverprofile=c.out
#go tool cover -html=c.out -o coverage.html 

