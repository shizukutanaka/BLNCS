# BLRCS Core Application
# Simplified architecture following Rob Pike's simplicity principle
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from .config import get_config, parse_rate_limit
from .database import Database
from .cache import Cache
from .logger import setup_logging, get_logger
from .rate_limiter import RateLimiter
from .i18n import Translator

# Initialize components
config = get_config()
logger = get_logger(__name__)
db = Database(config.db_path)
cache = Cache(config.cache_size, config.cache_ttl)
translator = Translator(config.default_lang, config.supported_langs)

# Rate limiter setup
rate_count, rate_period = parse_rate_limit(config.rate_limit)
rate_limiter = RateLimiter(rate_count, rate_period)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager"""
    # Startup
    logger.info(f"Starting {config.app_name}")
    await db.connect()
    await cache.initialize()
    
    yield
    
    # Shutdown
    logger.info(f"Shutting down {config.app_name}")
    await db.disconnect()
    await cache.clear()

# Create FastAPI app with minimal configuration
app = FastAPI(
    title=config.app_name,
    debug=config.debug,
    lifespan=lifespan,
    docs_url="/docs" if config.debug else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.debug else None
)

# Middleware for request tracking
@app.middleware("http")
async def track_requests(request: Request, call_next):
    """Track and log requests"""
    from uuid import uuid4
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    request.state.request_id = request_id
    
    # Check rate limit
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check(client_ip):
        return JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429,
            headers={"X-Request-ID": request_id}
        )
    
    # Process request
    start_time = datetime.utcnow()
    response = await call_next(request)
    duration = (datetime.utcnow() - start_time).total_seconds()
    
    # Add headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration:.3f}s"
    
    # Log request
    logger.info(
        f"Request processed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration": duration
        }
    )
    
    return response

# Core endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    checks = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": await db.health_check(),
        "cache": cache.health_check()
    }
    
    if all(v for k, v in checks.items() if k not in ["status", "timestamp"]):
        return JSONResponse(checks, status_code=200)
    else:
        checks["status"] = "degraded"
        return JSONResponse(checks, status_code=503)

@app.get("/info")
async def get_info():
    """Get application information"""
    return {
        "name": config.app_name,
        "mode": config.mode,
        "version": "1.0.0",
        "language": config.default_lang
    }

@app.post("/api/v1/process")
async def process_data(request: Request):
    """Main data processing endpoint"""
    try:
        data = await request.json()
        
        # Validate API key if configured
        if config.api_key:
            provided_key = request.headers.get("X-API-Key")
            if provided_key != config.api_key:
                raise HTTPException(status_code=401, detail="Invalid API key")
        
        # Process data
        result = await process_core_logic(data)
        
        # Cache result
        import hashlib
        cache_key = hashlib.sha256(str(data).encode()).hexdigest()
        await cache.set(cache_key, result)
        
        return JSONResponse({
            "success": True,
            "result": result,
            "cached": False
        })
        
    except Exception as e:
        logger.error(f"Processing error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def process_core_logic(data: Dict[str, Any]) -> Dict[str, Any]:
    """Core processing logic"""
    if not data:
        raise ValueError("Empty data")
    
    processed = {
        "processed_at": datetime.utcnow().isoformat(),
        "input_count": len(data),
        "items": []
    }
    
    for key, value in data.items():
        item = {
            "key": key,
            "value": value,
            "processed": True
        }
        processed["items"].append(item)
    
    if config.mode == "prod":
        await db.store_result(processed)
    
    return processed

def run():
    """Run the application"""
    setup_logging(config.log_level, config.log_file)
    
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
        reload=config.mode == "dev"
    )
