# go-toolkit

Reusable Go packages for building secure web services.

## Packages

| Package | Description |
|---|---|
| [`pkg/env`](pkg/env) | Typed environment variable helpers with fallback values |
| [`pkg/jwt`](pkg/jwt) | JWT manager for access tokens, refresh tokens, and OAuth exchange codes |
| [`pkg/ginmiddleware`](pkg/ginmiddleware) | Gin middleware for auth, CSRF, cookies, caching, and rate limiting |
| [`pkg/notify`](pkg/notify) | Operational notifications to a chat channel (Discord webhooks), with no secret in errors |

## Install

```
go get github.com/spectrum-labs-tech/go-toolkit
```

## Testing

```
task test
```
