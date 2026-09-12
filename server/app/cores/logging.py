# import dependencies
import logging, sys
from logging.config import dictConfig




# safe extra formatter
class SafeExtraFormatter(logging.Formatter):
    """
    Logging formatter that safely collects custom fields
    supplied through logging's `extra={...}` argument.
    """

    STANDARD_FIELDS = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "asctime",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
    }



    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log message and safely collect
        custom LogRecord fields.
        """

        message = super().format(record)

        extra = {
            key: value
            for key, value in record.__dict__.items()
            if key not in self.STANDARD_FIELDS
        }

        return f"{message} | {extra}"




# logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "default": {
            "()": SafeExtraFormatter,
            "format": (
                "%(asctime)s | "
                "%(levelname)s | "
                "%(name)s | "
                "%(message)s"
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




# setup logging
def setup_logging() -> None:
    """
    Configure application logging.
    """
    dictConfig(LOGGING_CONFIG)




# safe logger adapter
class SafeExtraAdapter(logging.LoggerAdapter):
    """
    LoggerAdapter that guarantees an `extra` dictionary
    is available when logging.
    """

    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})
        return msg, kwargs





# logger factory
def get_logger(name: str) -> logging.LoggerAdapter:
    """
    Return a logger for the application namespace.

    Example:
        logger = get_logger("cores.exceptions")

    Produces:
        app.cores.exceptions
    """

    base_logger = logging.getLogger(f"app.{name}")

    return SafeExtraAdapter(base_logger, {})
