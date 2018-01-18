# Use this makefile to create the binaries
# so that they get an auditable version compiled into them.

go=go
rev=$(shell git rev-parse --short HEAD)

all: build

build: clean certomat

vendor:
	dep ensure

clean:
	rm -f certomat

certomat: vendor
	GOOS=linux $(go) build -ldflags "-s -w -X main.gitRevision=$(rev)"

deploy-certodev: certomat
	scp certomat certodev@uf6:
	ssh root@uf6 setcap CAP_NET_BIND_SERVICE=+eip /home/certodev/certomat

deploy-certomat: certomat
	scp certomat certomat@uf6:
	ssh root@uf6 setcap CAP_NET_BIND_SERVICE=+eip /home/certomat/certomat
