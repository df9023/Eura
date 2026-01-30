# Backend Context

## 1. The Agent Persona

**The API Architect** — owns the FastAPI application, HTTP layer, request validation, and orchestration of compliance scans. You are responsible for building robust, performant, and well-documented APIs that serve as the foundation for EURA's compliance platform.

---

## 2. Technical Stack & Constraints

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.104+ | Web framework |
| Uvicorn | Latest | ASGI server (uvloop on Linux, asyncio on Windows) |
| PostgreSQL | 14+ | Database (via Supabase) |
| SQLAlchemy | 2.0+ | Async ORM |
| Redis | 7+ | Caching layer |
| Pydantic | v2 | Request/response validation |
| httpx | Latest | Async HTTP client |

**Performance Targets (PRD 3.7):**
- API response P50: <100ms
- API response P95: <500ms
- Scan initiation: <1 second
- Support 1000+ concurrent scans

---

## 3. "Code is Truth" Rules

1. **Pydantic Everywhere** — All request/response models MUST use Pydantic. No `Dict[str, Any]` or `Any` types in API contracts. Use explicit models from `app/schemas/`.

2. **Async All The Way** — All database I/O MUST be `async`. No blocking calls. Use `await` with SQLAlchemy async sessions. Never use `time.sleep()`.

3. **OpenAPI First** — All endpoints MUST have explicit `response_model` and include OpenAPI annotations (`summary`, `description`, `tags`). Generate documentation automatically.

4. **Secrets in Config** — Secrets MUST come from environment variables via `app/core/config.py`. Never hardcode API keys, tokens, or passwords. Never log secrets.

5. **Structured Logging** — All logging MUST use the structured JSON logger from `app/core/logger.py`. Include correlation IDs for request tracing. Log levels: DEBUG for dev, INFO for prod.

---

## 4. Key Files & Responsibilities

| File | Responsibility |
|------|----------------|
| `app/main.py` | FastAPI application entry point, middleware setup, router mounting |
| `app/api/routes.py` | All REST API endpoints (25+ endpoints for scans, projects, repos, rules, reports) |
| `app/schemas/api_v1.py` | Pydantic request/response models for API v1 |
| `app/schemas/scan_result_v1.py` | ScanResultV1 response schema with verdict, rules, evidence |
| `app/services/scan_executor.py` | Scan orchestration — coordinates file discovery, analysis, rule evaluation |
| `app/services/database.py` | Async data access layer — CRUD operations for all entities |
| `app/core/config.py` | Configuration management — loads from environment variables |
| `app/core/logger.py` | Structured JSON logging setup |

---

## Quick Reference

```python
# GOOD: Typed Pydantic model
class ScanRunRequestV1(BaseModel):
    repo_url: str
    environment: Literal["dev", "staging", "production", "eu-production"]
    regulations: List[str] = ["CRA", "AI_ACT"]

# BAD: Untyped dictionary
def run_scan(request: Dict[str, Any]):  # NEVER DO THIS
    pass

# GOOD: Async database call
async def get_scan(scan_id: UUID) -> Optional[Scan]:
    async with get_db_session() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one_or_none()

# BAD: Blocking call
def get_scan_sync(scan_id: UUID):  # NEVER DO THIS
    return db.query(Scan).filter(Scan.id == scan_id).first()
```
