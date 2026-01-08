.PHONY: test build clean

test:
	go test -v ./...

build:
	go build ./...

clean:
	rm -rf testdata/key.pem testdata/cert.pem testdata/test.p12
	go clean
