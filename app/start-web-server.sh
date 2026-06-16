#!/bin/sh

# use $PORT provided gy Google Cloud Run if available
API_PORT=${API_PORT:-$PORT}
# Set the default port if no environment variable is provided
API_PORT=${API_PORT:-8080}

echo "Starting application on port $API_PORT"

# Start the application with the given or default port.
# --timeout-keep-alive must exceed Cloud Run's connection idle window so that
# idle keep-alive connections are closed by the Cloud Run proxy, not by uvicorn.
# Otherwise the proxy may reuse a connection uvicorn just closed, surfacing as
# intermittent 503 "connection to the instance had an error".
exec uvicorn main:app --host 0.0.0.0 --port $API_PORT --timeout-keep-alive 620
