"""
Commercial Unified API Server
Enterprise-grade REST API with advanced features
"""

from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import asyncio
import uvicorn
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
import logging
import time
import json
from contextlib import asynccontextmanager

# Commercial components
from blncs.core.commercial_security import security_manager
from blncs.core.commercial_cache import cache_manager
from blncs.core.commercial_monitoring import monitoring_service
from blncs.core.commercial_logging import enterprise_logger, LogLevel, LogCategory
from blncs.core.commercial_performance_engine import performance_profiler, optimize_for_production
from blncs.core.human_interface_system import conversational_interface
from blncs.core.market_intelligence import market_intelligence

logger = logging.getLogger(__name__)
security = HTTPBearer()


# Pydantic models for API
class APIResponse(BaseModel):
    """Standard API response format"""
    success: bool
    data: Optional[Any] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    request_id: Optional[str] = None


class PaymentRequest(BaseModel):
    """Payment request model"""
    payment_request: str = Field(..., description="Lightning payment request")
    amount: Optional[int] = Field(None, description="Amount in satoshis")
    fee_limit: Optional[int] = Field(100, description="Maximum fee in satoshis")
    timeout: Optional[int] = Field(60, description="Payment timeout in seconds")


class InvoiceRequest(BaseModel):
    """Invoice creation request"""
    amount: int = Field(..., gt=0, description="Amount in satoshis")
    description: Optional[str] = Field("Lightning payment", description="Payment description")
    expiry: Optional[int] = Field(3600, description="Invoice expiry in seconds")
    private: Optional[bool] = Field(False, description="Private invoice")


class ChatMessage(BaseModel):
    """Chat message for conversational interface"""
    message: str = Field(..., min_length=1, max_length=1000)
    user_id: str = Field(..., description="User identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")


class PerformanceProfile(BaseModel):
    """Performance profile configuration"""
    profile: str = Field(..., description="Performance profile (latency, throughput, memory, battery, balanced)")


class MarketAnalysisRequest(BaseModel):
    """Market analysis request"""
    segment: str = Field(..., description="Market segment (enterprise, smb, developer, consumer)")
    analysis_type: str = Field("opportunity", description="Analysis type (opportunity, competitive, revenue)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    enterprise_logger.info("Starting commercial API server", category=LogCategory.SYSTEM)

    # Initialize commercial systems
    optimize_for_production()

    # Start monitoring if available
    if monitoring_service:
        await monitoring_service.start()

    enterprise_logger.info("Commercial API server started", category=LogCategory.SYSTEM)

    yield

    # Shutdown
    enterprise_logger.info("Shutting down commercial API server", category=LogCategory.SYSTEM)

    if monitoring_service:
        await monitoring_service.stop()


# Create FastAPI app with lifespan
app = FastAPI(
    title="BLNCS Commercial API",
    description="Commercial-grade Lightning Network Control System API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Validate JWT token and return user context"""
    try:
        token = credentials.credentials
        payload = security_manager.tokens.verify_token(token)

        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")

        return payload
    except Exception as e:
        enterprise_logger.warning(f"Authentication failed: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")


# Request logging middleware
@app.middleware("http")
async def log_requests(request, call_next):
    """Log all API requests"""
    start_time = time.time()

    # Create correlation ID
    import uuid
    correlation_id = str(uuid.uuid4())

    # Log request
    enterprise_logger.info(
        f"API Request: {request.method} {request.url.path}",
        category=LogCategory.ACCESS,
        data={
            'method': request.method,
            'path': request.url.path,
            'client_ip': request.client.host,
            'correlation_id': correlation_id
        }
    )

    # Execute request
    response = await call_next(request)

    # Calculate response time
    response_time = time.time() - start_time

    # Log response
    enterprise_logger.info(
        f"API Response: {response.status_code} ({response_time:.3f}s)",
        category=LogCategory.ACCESS,
        data={
            'status_code': response.status_code,
            'response_time': response_time,
            'correlation_id': correlation_id
        }
    )

    # Add headers
    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Response-Time"] = str(response_time)

    return response


# Rate limiting middleware (simplified)
request_counts = {}
RATE_LIMIT = 1000  # requests per hour

@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    """Simple rate limiting"""
    client_ip = request.client.host
    current_time = time.time()

    # Clean old entries
    cutoff_time = current_time - 3600  # 1 hour ago
    request_counts[client_ip] = [
        timestamp for timestamp in request_counts.get(client_ip, [])
        if timestamp > cutoff_time
    ]

    # Check rate limit
    if len(request_counts.get(client_ip, [])) >= RATE_LIMIT:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"}
        )

    # Record request
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    request_counts[client_ip].append(current_time)

    return await call_next(request)


# Health check endpoint
@app.get("/health", response_model=APIResponse)
async def health_check():
    """Health check endpoint for load balancers"""
    try:
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now(),
            "version": "1.0.0",
            "uptime": time.time(),
            "components": {
                "api": "healthy",
                "security": "healthy" if security_manager else "unavailable",
                "cache": "healthy" if cache_manager else "unavailable",
                "monitoring": "healthy" if monitoring_service else "unavailable"
            }
        }

        return APIResponse(success=True, data=health_data)

    except Exception as e:
        enterprise_logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


# Authentication endpoints
@app.post("/auth/login")
async def login(username: str, password: str, mfa_token: Optional[str] = None):
    """Authenticate user and return JWT tokens"""
    try:
        result = await security_manager.authenticate(
            username=username,
            password=password,
            mfa_token=mfa_token
        )

        if not result:
            enterprise_logger.warning(f"Login failed for user: {username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")

        enterprise_logger.info(f"User logged in: {username}", category=LogCategory.AUDIT)

        return APIResponse(success=True, data=result)

    except HTTPException:
        raise
    except Exception as e:
        enterprise_logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Authentication error")


# Lightning Network endpoints
@app.get("/lightning/info")
async def get_lightning_info(current_user: dict = Depends(get_current_user)):
    """Get Lightning node information"""
    try:
        # Simulate Lightning node info
        info = {
            "public_key": "02a1b2c3d4e5f6...",
            "alias": "BLNCS-Commercial-Node",
            "network": "mainnet",
            "version": "1.0.0",
            "block_height": 750000,
            "synced": True,
            "num_peers": 25,
            "num_channels": 12,
            "num_active_channels": 10
        }

        return APIResponse(success=True, data=info)

    except Exception as e:
        enterprise_logger.error(f"Error getting Lightning info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Lightning info")


@app.get("/lightning/balance")
async def get_lightning_balance(current_user: dict = Depends(get_current_user)):
    """Get Lightning wallet balance"""
    try:
        # Simulate balance data
        balance = {
            "total_balance": 1500000,  # 1.5M sats
            "confirmed_balance": 1450000,
            "unconfirmed_balance": 50000,
            "channel_balance": {
                "local_balance": 800000,
                "remote_balance": 700000
            }
        }

        return APIResponse(success=True, data=balance)

    except Exception as e:
        enterprise_logger.error(f"Error getting balance: {e}")
        raise HTTPException(status_code=500, detail="Failed to get balance")


@app.post("/lightning/pay")
async def send_payment(
    payment: PaymentRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Send Lightning payment"""
    try:
        # Log payment attempt
        enterprise_logger.audit(
            event_type="payment_initiated",
            action="send_payment",
            resource="lightning_network",
            result="pending",
            user_id=current_user.get("sub"),
            metadata={
                "amount": payment.amount,
                "payment_request": payment.payment_request[:20] + "..."
            }
        )

        # Simulate payment processing
        payment_hash = "abc123def456ghi789"

        # Background task for payment status updates
        background_tasks.add_task(process_payment_async, payment_hash, current_user)

        result = {
            "payment_hash": payment_hash,
            "status": "pending",
            "amount": payment.amount,
            "fee": 10  # 10 sats fee
        }

        return APIResponse(success=True, data=result, message="Payment initiated")

    except Exception as e:
        enterprise_logger.error(f"Payment error: {e}")
        raise HTTPException(status_code=500, detail="Payment failed")


@app.post("/lightning/invoice")
async def create_invoice(
    invoice: InvoiceRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create Lightning invoice"""
    try:
        # Generate mock invoice
        import secrets
        r_hash = secrets.token_hex(32)
        payment_request = f"lnbc{invoice.amount}u1p{secrets.token_hex(20)}..."

        # Log invoice creation
        enterprise_logger.audit(
            event_type="invoice_created",
            action="create_invoice",
            resource="lightning_network",
            result="success",
            user_id=current_user.get("sub"),
            metadata={
                "amount": invoice.amount,
                "description": invoice.description
            }
        )

        result = {
            "r_hash": r_hash,
            "payment_request": payment_request,
            "amount": invoice.amount,
            "description": invoice.description,
            "expiry": invoice.expiry,
            "created_at": datetime.now()
        }

        return APIResponse(success=True, data=result, message="Invoice created")

    except Exception as e:
        enterprise_logger.error(f"Invoice creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create invoice")


# Conversational AI endpoints
@app.post("/chat")
async def chat_with_ai(
    message: ChatMessage,
    current_user: dict = Depends(get_current_user)
):
    """Chat with conversational AI interface"""
    try:
        response = await conversational_interface.process_message(
            user_id=message.user_id,
            message=message.message
        )

        return APIResponse(success=True, data=response)

    except Exception as e:
        enterprise_logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail="Chat processing failed")


# Performance optimization endpoints
@app.post("/system/performance/profile")
async def set_performance_profile(
    profile: PerformanceProfile,
    current_user: dict = Depends(get_current_user)
):
    """Set system performance profile"""
    try:
        from blncs.core.commercial_performance_engine import PerformanceProfile as PerfProfile

        profile_map = {
            "latency": PerfProfile.LATENCY_OPTIMIZED,
            "throughput": PerfProfile.THROUGHPUT_OPTIMIZED,
            "memory": PerfProfile.MEMORY_OPTIMIZED,
            "battery": PerfProfile.BATTERY_OPTIMIZED,
            "balanced": PerfProfile.BALANCED
        }

        if profile.profile not in profile_map:
            raise HTTPException(status_code=400, detail="Invalid performance profile")

        performance_profiler.set_performance_profile(profile_map[profile.profile])

        return APIResponse(
            success=True,
            message=f"Performance profile set to {profile.profile}"
        )

    except Exception as e:
        enterprise_logger.error(f"Performance profile error: {e}")
        raise HTTPException(status_code=500, detail="Failed to set performance profile")


@app.get("/system/performance/metrics")
async def get_performance_metrics(current_user: dict = Depends(get_current_user)):
    """Get system performance metrics"""
    try:
        metrics = performance_profiler.get_performance_summary()
        return APIResponse(success=True, data=metrics)

    except Exception as e:
        enterprise_logger.error(f"Performance metrics error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")


# Market intelligence endpoints
@app.post("/market/analysis")
async def get_market_analysis(
    request: MarketAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """Get market intelligence analysis"""
    try:
        from blncs.core.market_intelligence import MarketSegment

        segment_map = {
            "enterprise": MarketSegment.ENTERPRISE,
            "smb": MarketSegment.SMB,
            "developer": MarketSegment.DEVELOPER,
            "consumer": MarketSegment.CONSUMER
        }

        if request.segment not in segment_map:
            raise HTTPException(status_code=400, detail="Invalid market segment")

        segment = segment_map[request.segment]

        if request.analysis_type == "opportunity":
            analysis = market_intelligence.analyze_market_opportunity(segment)
        elif request.analysis_type == "strategy":
            analysis = market_intelligence.generate_go_to_market_strategy(segment)
        else:
            analysis = market_intelligence.get_market_intelligence_summary()

        return APIResponse(success=True, data=analysis)

    except Exception as e:
        enterprise_logger.error(f"Market analysis error: {e}")
        raise HTTPException(status_code=500, detail="Market analysis failed")


# Monitoring endpoints
@app.get("/monitoring/metrics")
async def get_monitoring_metrics(current_user: dict = Depends(get_current_user)):
    """Get system monitoring metrics"""
    try:
        if monitoring_service:
            metrics = monitoring_service.get_metrics_summary()
        else:
            metrics = {"status": "monitoring_unavailable"}

        return APIResponse(success=True, data=metrics)

    except Exception as e:
        enterprise_logger.error(f"Monitoring metrics error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get monitoring metrics")


@app.get("/monitoring/alerts")
async def get_active_alerts(current_user: dict = Depends(get_current_user)):
    """Get active system alerts"""
    try:
        if monitoring_service:
            alerts = monitoring_service.alerting_engine.get_alert_summary()
        else:
            alerts = {"status": "monitoring_unavailable"}

        return APIResponse(success=True, data=alerts)

    except Exception as e:
        enterprise_logger.error(f"Alerts error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")


# Security audit endpoints
@app.get("/security/audit")
async def get_security_audit(current_user: dict = Depends(get_current_user)):
    """Get security audit log"""
    try:
        audit_data = security_manager.auditor.get_audit_log()
        return APIResponse(success=True, data=audit_data)

    except Exception as e:
        enterprise_logger.error(f"Security audit error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security audit")


# Cache management endpoints
@app.post("/cache/clear")
async def clear_cache(current_user: dict = Depends(get_current_user)):
    """Clear system cache"""
    try:
        if cache_manager:
            await cache_manager.cache.clear()
            message = "Cache cleared successfully"
        else:
            message = "Cache manager unavailable"

        return APIResponse(success=True, message=message)

    except Exception as e:
        enterprise_logger.error(f"Cache clear error: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear cache")


# WebSocket endpoints for real-time updates
@app.websocket("/ws/updates")
async def websocket_updates(websocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()

    try:
        while True:
            # Send periodic updates
            update = {
                "timestamp": datetime.now().isoformat(),
                "type": "status_update",
                "data": {
                    "online": True,
                    "channels": 10,
                    "balance": 1500000
                }
            }

            await websocket.send_json(update)
            await asyncio.sleep(30)  # Send updates every 30 seconds

    except Exception as e:
        enterprise_logger.warning(f"WebSocket error: {e}")
    finally:
        await websocket.close()


# Background task for payment processing
async def process_payment_async(payment_hash: str, user: dict):
    """Background task to process payment"""
    try:
        # Simulate payment processing delay
        await asyncio.sleep(2)

        # Log payment completion
        enterprise_logger.audit(
            event_type="payment_completed",
            action="payment_processed",
            resource="lightning_network",
            result="success",
            user_id=user.get("sub"),
            metadata={"payment_hash": payment_hash}
        )

    except Exception as e:
        enterprise_logger.error(f"Background payment processing error: {e}")


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "timestamp": datetime.now().isoformat()
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    enterprise_logger.error(f"Unhandled exception: {exc}")

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": 500,
                "message": "Internal server error",
                "timestamp": datetime.now().isoformat()
            }
        }
    )


def create_commercial_api_app() -> FastAPI:
    """Create and configure commercial API application"""
    return app


def run_commercial_api_server(host: str = "0.0.0.0", port: int = 8080):
    """Run the commercial API server"""
    uvicorn.run(
        "blncs.api.commercial_unified_api:app",
        host=host,
        port=port,
        reload=False,
        workers=1,
        log_level="info"
    )


if __name__ == "__main__":
    run_commercial_api_server()