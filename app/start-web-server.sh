#!/bin/sh

# use $PORT provided gy Google Cloud Run if available
API_PORT=${API_PORT:-$PORT}
# Set the default port if no environment variable is provided
API_PORT=${API_PORT:-8080}

echo "Starting application on port $API_PORT"

# Start the application with the given or default port
exec uvicorn main:app --host 0.0.0.0 --port $API_PORT
