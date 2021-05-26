.PHONY: all install fmt test

all:
	env GO111MODULE=on go build -v ./...

install:
	env GO111MODULE=on go install -v ./...

fmt:
	pandoc -o tmp.md -s README.md
	mv tmp.md README.md

test:
	env GO111MODULE=on go test -cover -v ./...
