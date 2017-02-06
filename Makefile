# Use this makefile to create the binaries
# so that they get an auditable version compiled into them.

go=go1.8rc2
rev=$(shell git rev-parse --short HEAD)

all: image

build: clean certomat

clean:
	rm -f certomat

certomat:
	CGO_ENABLED=0 GOOS=linux $(go) build -a -installsuffix cgo \
		-ldflags "-s -w -X main.gitRevision=$(rev)"

image: build
	docker build -t unifield/certomat:$(rev) .
	docker push unifield/certomat:$(rev)

