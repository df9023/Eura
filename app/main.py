"""FastAPI application entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import allow_origins
from app.core.logger import logger
from app.api.routes import router

# Log CORS configuration
logger.info("CORS: Allowed origins configured as: %s", allow_origins)

# Initialize FastAPI app with OpenAPI metadata
app = FastAPI(
    title="EURA 2.0 — EU Compliance Scanner API",
    description=(
        "**EURA** evaluates software repositories against the **EU Cyber Resilience Act (CRA)** "
        "and **EU AI Act** for compliance.\n\n"
        "## Capabilities\n"
        "- **Scan** GitHub repositories or local directories for CRA/AI Act compliance\n"
        "- **35 CRA rules** across 5 categories: BASE, SEC, VULN, DOC, LIFE\n"
        "- **OSV vulnerability scanning** against osv.dev for known CVEs\n"
        "- **Compliance artifacts**: SBOM (SPDX/CycloneDX), SARIF 2.1.0, badges (SVG)\n"
        "- **Verdict engine**: SHIP_ALLOWED / SHIP_BLOCKED with evidence-based scoring\n\n"
        "## Quick Start\n"
        "```\nPOST /api/v1/scan          — Run a compliance scan\n"
        "GET  /api/v1/rules          — List all compliance rules\n"
        "POST /api/v1/sbom/generate  — Generate SBOM from dependencies\n"
        "POST /api/v1/exports/sarif  — Export SARIF 2.1.0 report\n"
        "GET  /api/v1/badges/{id}    — Get compliance badge (SVG)\n```"
    ),
    version="2.0.0",
    contact={"name": "EURA Compliance", "url": "https://github.com/eura-compliance/eura"},
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    openapi_tags=[
        {"name": "API", "description": "All EURA v1 API endpoints"},
    ],
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
app.include_router(router, prefix="/api", tags=["API"])

