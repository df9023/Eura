"""FastAPI application entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import allow_origins
from app.core.logger import logger
from app.api.routes import router

# Log CORS configuration
logger.info("CORS: Allowed origins configured as: %s", allow_origins)

# Initialize FastAPI app
app = FastAPI(
    title="Repository Scanner API",
    description="API for scanning GitHub repositories using GitHub App authentication",
    version="1.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)

# Include API routes
app.include_router(router)

