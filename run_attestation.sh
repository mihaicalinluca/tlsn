#!/bin/bash

# Make the script executable
# chmod +x run_attestation.sh

# Cleanup background processes on script exit
trap 'kill $(jobs -p) 2>/dev/null' EXIT

VERBOSE=true

if [ "$VERBOSE" = true ]; then
    echo "Verbose mode is enabled"
else
    echo "Verbose mode is disabled"
fi

# Start the server-fixture with custom API
echo "Starting server-fixture..."
CUSTOM_API_URL="https://api.multiversx.com/stats" 
PORT=4000 cargo run --bin tlsn-server-fixture &
sleep 2

# Start the notary server  
echo "Starting notary server..."
cd crates/notary/server
cargo run -r -- --tls-enabled false &
sleep 2

# Start the prover and run the attestation prove example
echo "Starting attestation prove..."
cd ../../../
RUST_LOG=debug,yamux=info,uid_mux=info SERVER_PORT=4000 cargo run --release --example attestation_prove