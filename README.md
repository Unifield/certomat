# certomat
A server to help Unifield instances get certificates

# Building certomat

You need Go 1.8 installed. It should be in your path via the name "go1.8". GOPATH should be set (best to just use $HOME/go).

Normally Go versions should not matter, but we want to build with Go 1.8 because of important SSL performance
improvements that are first available in Go 1.8. Normally Go binaries can be built with nothing more than
"go build", but we want to put the Git revision into the binary for tracability reasons, so we need to use make.

    go get github.com/Unifield/certomat
    cd $GOPATH/src/github.com/Unifield/certomat
    make
    scp certomat certomat@uf6:

## Setup certbot

    # As root
    useradd -m certomat
    su - certomat

    # As user certomat
    virtualenv venv
    . venv/bin/activate
    # Make this Python able to bind to ports under 1024
    sudo setcap CAP_NET_BIND_SERVICE=+eip venv/bin/python2
    pip install certbot

Apply the hack to let it listen on uf6-2.unifield.org only:

    Edit venv/lib/python2.7/site-packages/certbot/plugins/standalone.py
    change address = ("", port) to address = ("178.33.173.98", port)

For ~certodev, make it listen to uf6-4, 178.33.173.100 instead. We need to submit a patch to certbot's maintainers that makes this possible to change from the commandline.

## Running it

    ./certomat > certomat.log 2>&1 &
