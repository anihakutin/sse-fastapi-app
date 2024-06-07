import asyncio
import os
from fastapi import FastAPI, Depends, HTTPException, Request, APIRouter
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Dict
from sse-fastapi-app.utils import authenticate_client_token, authenticate_m2m_token
from loguru import logger
import jwt  # This is PyJWT, not the jwt library

load_dotenv()


def init_jwks_client(app: FastAPI) -> None:
    # This gets the JWKS from a given URL and does processing so you can
    # use any of the keys available
    domain = os.getenv("DOMAIN")
    logger.info(f"Initializing JWKS client for domain {domain}")

    jwks_url = f"https://{domain}/.well-known/jwks.json"
    app.state.jwks_client = jwt.PyJWKClient(
        jwks_url, cache_jwk_set=True, lifespan=604800
    )


app = FastAPI()
init_jwks_client(app)
api_router = APIRouter()


# In-memory storage for event sources
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, asyncio.Queue] = {}

    async def connect(self, user_id: str):
        queue = asyncio.Queue()
        self.active_connections[user_id] = queue
        return queue

    async def disconnect(self, user_id: str):
        self.active_connections.pop(user_id, None)

    async def send_event(self, user_id: str, message: str):
        queue = self.active_connections.get(user_id)
        if queue:
            await queue.put(message)


connection_manager = ConnectionManager()


class EventMessage(BaseModel):
    user_id: str
    message: str


@api_router.get("/subscribe", dependencies=[Depends(authenticate_client_token)])
async def get_events(request: Request):
    try:
        user_id = request.state.user["sub"]
        queue = await connection_manager.connect(user_id)

        async def event_generator():
            try:
                while True:
                    message = await queue.get()
                    yield f"data: {message}\n\n"
            except asyncio.CancelledError:
                await connection_manager.disconnect(user_id)
                raise

        return EventSourceResponse(event_generator(), ping=10)
    except AttributeError:
        raise HTTPException(status_code=401, detail="Invalid token")


@api_router.post("/trigger_event", dependencies=[Depends(authenticate_m2m_token)])
async def trigger_event(event: EventMessage, request: Request):
    await connection_manager.send_event(event.user_id, event.message)
    return {"message": "Event triggered"}

app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
