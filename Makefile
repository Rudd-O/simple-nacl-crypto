.PHONY: deps fmt

deplist = src/github.com/golang/crypto \
	src/github.com/Rudd-O/simple-nacl-crypto

objlist = bin/nacl-crypt

all: $(objlist)

deps: $(deplist)

src/github.com/Rudd-O/simple-nacl-crypto:
	mkdir -p `dirname $@`
	ln -s ../../.. $@

src/github.com/%:
	mkdir -p `dirname $@`
	cd `dirname $@` && git clone `echo $@ | sed 's|src/|https://|'`
	if [[ $@ == src/github.com/golang* ]] ; then mkdir -p src/golang.org/x ; ln -sf ../../../$@ src/golang.org/x/ ; fi

bin/%: deps
	GOPATH=$(PWD) go install github.com/Rudd-O/simple-nacl-crypto/cmd/`echo $@ | sed 's|bin/||'`

fmt:
	for f in *.go cmd/*/*.go ; do gofmt -w "$$f" || exit 1 ; done

test:
	GOPATH=$(PWD) go test
