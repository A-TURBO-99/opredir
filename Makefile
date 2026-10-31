.PHONY: test build vet clean

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -o bin/opredir ./cmd/opredir

clean:
	rm -rf bin generated-cases.jsonl responses.jsonl
