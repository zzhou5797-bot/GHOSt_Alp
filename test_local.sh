#!/bin/bash
set -e

echo "Starting server..."
cargo run --bin server -- --port 8080 --ca certs/ca.crt --cert certs/server.crt --key certs/server.key --token secret-token &
SERVER_PID=$!

sleep 3

echo "Testing health probe..."
curl -s http://127.0.0.1:8081/healthz
echo ""

echo "Server is running (PID: $SERVER_PID). Try connecting with the client:"
echo "cargo run --bin client -- --host 127.0.0.1 --port 8080 --ca certs/ca.crt --cert certs/client.crt --key certs/client.key --token secret-token"
echo "To kill server: kill $SERVER_PID"
