PROJECTNAME=$(shell basename "$(PWD)")

help: Makefile
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'

## build: Builds binary for current architecture 
build:
	@echo "Building for local architecture"
	go build -o Ipss

## buildbsd: Builds binary for FreeBSD
buildbsd:
	@echo "Building for freebsd"
	GOOS=freebsd GOARCH=amd64 go build -o Ipss-freebsd
