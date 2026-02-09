from typing import cast
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.pool import QueuePool 

from app.core.db import get_db, engine

router = APIRouter()

@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    Health check ensuring all critical services are reachable.
    """
    status = {"status": "healthy", "dependencies": {}}
    
    try:
        db.execute(text("SELECT 1"))
        status["dependencies"]["database"] = "up"
    except Exception as e:
        status["dependencies"]["database"] = f"down: {str(e)}"
        status["status"] = "unhealthy"

    try:
        pool = cast(QueuePool, engine.pool)
        
        status["pool_stats"] = {
            "checkedin": pool.checkedin(),
            "checkedout": pool.checkedout(),
            "overflow": pool.overflow(),
            "size": pool.size()
        }
    except AttributeError:
        status["pool_stats"] = "not_available (using NullPool?)"
    except Exception as e:
        status["pool_stats"] = f"error: {str(e)}"
    
    return status