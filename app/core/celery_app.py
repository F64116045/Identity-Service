from celery import Celery
from app.core.config import settings


celery_app = Celery(
    "worker",
    broker=f"redis://{settings.POSTGRES_SERVER}:6379/0",
    backend=f"redis://{settings.POSTGRES_SERVER}:6379/0",
    include=[
        "app.tasks.email",
    ]
)


celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_max_tasks_per_child=1000,
)