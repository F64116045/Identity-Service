import logging
import sys
import structlog

def setup_logging():
    wrapped_logger = structlog.stdlib.LoggerFactory()

    shared_processors = [
        structlog.contextvars.merge_contextvars, 
        structlog.processors.add_log_level,       
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,      
    ]

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=wrapped_logger,
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    handler = logging.StreamHandler(sys.stdout)
    
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer() if sys.stdout.isatty() else structlog.processors.JSONRenderer(),
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy.engine"):
        target_logger = logging.getLogger(logger_name)
        target_logger.handlers = [handler]
        target_logger.propagate = False
        target_logger.setLevel(logging.WARNING)

logger: structlog.stdlib.BoundLogger = structlog.get_logger()