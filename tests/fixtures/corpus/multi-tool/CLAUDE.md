# Project Instructions

A Go microservice for user authentication.

## Development

- Go 1.22+
- Run tests: `go test ./...`
- Build: `go build -o bin/server ./cmd/server`

## Deployment

Use the deploy skill for staging and production deployments. Always run tests before deploying.

## Code review

- Check for SQL injection in query builders
- Verify error handling on all database calls
- Ensure JWT tokens have reasonable expiration
