"""Main FastAPI Application Entrypoint for DRISTHI Central Backend."""

import os
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT", "1")

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.routes import (
    health,
    ingestion,
    events,
    attackers,
    sessions,
    dashboard,
    websocket,
    tenants,
    assets,
    honeytokens,
    deployments,
)
from backend.app.core.config import settings
from backend.app.core.exceptions import DrishtiException
from backend.app.core.logging import logger
from backend.app.database.connection import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize tables if not already created
    logger.info("Starting up %s v%s...", settings.PROJECT_NAME, settings.VERSION)
    try:
        init_db()
    except Exception as exc:
        logger.warning("Auto schema init deferred (using existing migrations/tables): %s", exc)
    yield
    logger.info("Shutting down %s...", settings.PROJECT_NAME)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Central Backend, Relational Persistence, Session Management, and Threat Intelligence for DRISTHI.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handler: Never expose raw database stack traces
@app.exception_handler(DrishtiException)
async def drishti_exception_handler(request: Request, exc: DrishtiException):
    logger.warning("Domain exception on %s: %s", request.url.path, exc.message)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": exc.message, "details": exc.details},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled server error on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "An internal server error occurred. Telemetry processing failed safely."},
    )


# Include API Routers
app.include_router(health.router, prefix=settings.API_V1_PREFIX, tags=["Health"])
app.include_router(ingestion.router, prefix=settings.API_V1_PREFIX, tags=["Ingestion"])
app.include_router(events.router, prefix=settings.API_V1_PREFIX, tags=["Attack Events"])
app.include_router(attackers.router, prefix=settings.API_V1_PREFIX, tags=["Attacker Profiles"])
app.include_router(sessions.router, prefix=settings.API_V1_PREFIX, tags=["Attacker Sessions"])
app.include_router(dashboard.router, prefix=settings.API_V1_PREFIX, tags=["Dashboard Analytics"])
app.include_router(tenants.router, prefix=settings.API_V1_PREFIX, tags=["Tenants"])
app.include_router(assets.router, prefix=settings.API_V1_PREFIX, tags=["Deceptive Assets"])
app.include_router(honeytokens.router, prefix=settings.API_V1_PREFIX, tags=["Honeytokens"])
app.include_router(deployments.router, prefix=settings.API_V1_PREFIX, tags=["Deployments"])
app.include_router(websocket.router, tags=["WebSockets"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=False)

