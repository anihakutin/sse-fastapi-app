# SSE fastAPI Server template
A barebones SSE server for communicating with a web client.

This project is a simple server that listens for incoming connections from a subscriber and sends them messages in the form of Server-Sent Events (SSE). 
The server is written in Python and uses the FastAPI framework.

## Installation
1. Clone the repo
2. Install the dependencies with `poetry install`
3. Run the server with `poetry run uvicorn sse-fastapi-app.main:app --reload --port 8001`

## Usage
The server will listen for incoming connections on `http://localhost:8000`.

To test the server, you can use the `curl` command to send a GET request to the server. This endpoint can be accessed with a client access token.
  
  ```bash       
  curl -X GET http://localhost:8001/subscribe
      -H "Authorization : Bearer 123"
  ```

The server will respond with a message in the form of an SSE when triggered.

To trigger the server to send a message, you can use the `curl` command to send a POST request to the server using an M2M token. The body of the request should contain the data you want to send to the client portal. 

  ```bash
  curl -X POST http://localhost:8001/trigger_event
      -H "Authorization : Bearer 123"
      -H "Content-Type: application/json"
      -d '{"user_id": "abc123", "message": "Hello SSE!"}'
  ```

## Environment Variables
### The server uses environment variables to configure the server. The following environment variables are used:

SECRET_KEY=secret
ALGORITHM=HS256
DOMAIN=sample-app.us.auth0.com

### Machine to Machine access token verification
M2M_ALGORITHMS=RS256
M2M_API_AUDIENCE=https://abc123.com/
M2M_ISSUER=https://abc123.us.auth0.com/

### Client access token verification 
ALGORITHMS=RS256
API_AUDIENCE=https://abc123.us.auth0.com/api/v2/
ISSUER=https://abc123.us.auth0.com/