# Use this makefile to create the binaries
# so that they get an auditable version compiled into them.

go=go1.8
rev=$(shell git rev-parse --short HEAD)

all: build

build: clean certomat

clean:
	rm -f certomat

certomat:
	GOOS=linux $(go) build -ldflags "-s -w -X main.gitRevision=$(rev)"

setcap: certomat
	sudo setcap CAP_NET_BIND_SERVICE=+eip certomat

# Compile with special flags for installing in a Docker scratch container
certomat-docker:
	CGO_ENABLED=0 GOOS=linux $(go) build -a -installsuffix cgo \
		-ldflags "-s -w -X main.gitRevision=$(rev)"

image: clean certomat-docker
	docker build -t unifield/certomat:$(rev) .
	docker push unifield/certomat:$(rev)

