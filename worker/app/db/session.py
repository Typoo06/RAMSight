# Worker database engine and connection helpers.

from sqlalchemy import create_engine

from app.core.config import get_settings

settings = get_settings()

engine = create_engine(settings.database_url, pool_pre_ping=True)

