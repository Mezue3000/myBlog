# import dependencies
import logging
import sys
from logging.config import dictConfig



# initialize logging params
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
        },
    },
}




# function to setup logs
def setup_logging():
    dictConfig(LOGGING_CONFIG)
    
    
    

# funtion to get logger
def get_logger(name: str):
    return logging.getLogger(f"app.{name}")