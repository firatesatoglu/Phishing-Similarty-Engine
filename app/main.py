from fastapi import FastAPI
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.database.mongodb import mongodb
from app.api.routes import health_router, search_router, algorithms_router

logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting Similarity Engine Service...")
    await mongodb.connect()
    logger.info("Similarity Engine Service started successfully")
    
    yield
    
    logger.info("Shutting down Similarity Engine Service...")
    await mongodb.disconnect()
    logger.info("Similarity Engine Service stopped")


app = FastAPI(
    title="Similarity Engine Service",
    description="Phishing detection using typosquatting and similarity algorithms",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/",
    redoc_url="/redoc"
)

app.include_router(health_router)
app.include_router(search_router)
app.include_router(algorithms_router)
