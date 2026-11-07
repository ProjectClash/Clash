# The Apple targets only: this copy keeps no other platform's files (CLASH_PATCH.md).
build:
	GOOS=darwin GOARCH=arm64 go build -v .
	GOOS=ios GOARCH=arm64 go build -v .

fmt:
	@golangci-lint fmt

lint:
	GOOS=darwin golangci-lint --max-same-issues=0 --max-issues-per-linter=0 run ./...

lint_install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

test:
	go build -v .
	#go test -bench=. ./internal/checksum_test
	go test -v $(TEST_FLAGS) .
