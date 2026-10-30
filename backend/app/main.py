from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging_config import logger, setup_logging
from app.db import entities  # noqa: F401 - ensure models are registered
from app.db.database import Base, engine, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: configure logging and ensure database tables exist
    setup_logging()
    logger.info("Initializing database tables and schema...")
    init_db()
    logger.info(f"{settings.APP_NAME} backend initialized successfully in {settings.APP_ENV} mode.")
    yield
    # Shutdown
    logger.info(f"{settings.APP_NAME} backend shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    description="AEGIS – AI-Powered Phishing Detection and Browser Protection System REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Register centralized exception handlers
register_exception_handlers(app)

# Configure CORS for frontend and Chrome extension compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=r"^(chrome-extension://.*|http://(localhost|127\.0\.0\.1)(:[0-9]+)?)$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"]
)

# Mount API routers
app.include_router(
    router,
    prefix=settings.API_PREFIX
)


@app.get(
    "/",
    summary="Root Information",
    description="Returns high-level backend identity and service status."
)
def root():
    return {
        "app_name": settings.APP_NAME,
        "service": "AEGIS Phishing Detection API",
        "status": "online",
        "version": "1.0.0",
        "docs_url": "/docs",
        "api_prefix": settings.API_PREFIX
    }