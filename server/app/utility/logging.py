# import dependencies
import logging
import sys
from logging.config import dictConfig
from typing import Any, Dict




LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": (
                "%(asctime)s | %(levelname)s | %(name)s | "
                "%(message)s | %(extra)s"
            ),
        },
    },
    
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": sys.stdout,
        },
    },
    
    "loggers": {
        "app": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
    },
}




def setup_logging():
    dictConfig(LOGGING_CONFIG)




class SafeExtraAdapter(logging.LoggerAdapter):
    # Ensures `extra` always exists to avoid KeyError in formatters
    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})
        kwargs["extra"].setdefault("extra", {})  
        return msg, kwargs




# function to get logger
def get_logger(name: str) -> logging.LoggerAdapter:
    base_logger = logging.getLogger(f"app.{name}")
    return SafeExtraAdapter(base_logger, {})
