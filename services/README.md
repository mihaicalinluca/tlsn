# TLSN Service Architecture

This directory contains a service-oriented approach to TLS notarization, providing HTTP APIs for both prover and notary components.

## Overview

The service architecture transforms the TLSN library components into persistent services with REST APIs, making it easier to integrate TLS notarization into web applications and automation workflows.

## Testing

- turn on notary server

```shell
cd crates/notary/server
cargo run -r -- --tls-enabled false
```

- turn on prover service

```shell
cd prover-service
cargo run --release
```

- call any of these endpoints

```rust
    POST /start_mpc - Start MPC session
    GET  /status/:session_id - Get session status
    GET  /sessions - List all sessions
    GET  /attestation/:session_id - Get attestation (JSON)
    GET  /transcript/:session_id - Get the http transcript of a completed session
    GET  /download/attestation/:session_id - Download attestation file
    GET  /download/secrets/:session_id - Download secrets file
    GET  /download/both/:session_id - Download both files (ZIP with .tlsn files)
    GET  /health - Health check
    GET  /info - Service information
```

### Example workflow

1) Turn on notary and prover-service

2) Start an MPC session

```shell
curl -X POST http://localhost:8080/start_mpc \
  -H "Content-Type: application/json" \
  -d '{
    "target_api": "https://api.multiversx.com/stats",
    "method": "GET",
    "headers": {}
  }'
```

3) Retrieve information about the session

```shell
curl http://localhost:8080/sessions
curl http://localhost:8080/status/2bc2e7d4-b367-4bbe-a175-b7ff6814ac15                     
```

4) Download attestation and secrets files when the session is completed (this also triggers session deletion for memory optimization)

```shell
# These download each file separately and do not trigger session deletion
# Session is automatically deleted after 30 minutes
curl -O -J http://localhost:8080/download/attestation/2bc2e7d4-b367-4bbe-a175-b7ff6814ac15
curl -O -J http://localhost:8080/download/secrets/2bc2e7d4-b367-4bbe-a175-b7ff6814ac15

# This downloads a zip containing both files and also triggers session deletion
curl -O -J http://localhost:8080/download/both/2bc2e7d4-b367-4bbe-a175-b7ff6814ac15
```

5) Get the transcript of a completed session

```shell
curl http://localhost:8080/transcript/b3a665f6-68dd-4f67-b862-01433d059eff
```
