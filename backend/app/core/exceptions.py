import logging
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("aegis")


class AEGISException(Exception):
    """Base exception for AEGIS system."""
    def __init__(self, message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ResourceNotFoundException(AEGISException):
    """Raised when a requested resource does not exist."""
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message=message, status_code=status.HTTP_404_NOT_FOUND)


class InvalidDecisionException(AEGISException):
    """Raised when an invalid user decision is submitted."""
    def __init__(self, message: str = "Invalid decision submitted"):
        super().__init__(message=message, status_code=status.HTTP_400_BAD_REQUEST)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handles Pydantic validation errors consistently."""
    errors = []
    for err in exc.errors():
        field_loc = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append({
            "field": field_loc,
            "message": err.get("msg", "Invalid value"),
            "type": err.get("type", "value_error")
        })

    logger.warning(f"Validation failed for request to {request.url.path}: {errors}")
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "error_type": "validation_error",
            "message": "Request validation failed",
            "details": errors
        }
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handles standard HTTP exceptions without exposing sensitive details."""
    logger.info(f"HTTP {exc.status_code} on {request.url.path}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error_type": "http_error",
            "message": exc.detail
        }
    )


async def aegis_exception_handler(request: Request, exc: AEGISException) -> JSONResponse:
    """Handles custom AEGIS application exceptions."""
    logger.warning(f"Application exception on {request.url.path}: {exc.message}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error_type": "application_error",
            "message": exc.message
        }
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catches all unexpected exceptions.
    Logs the full traceback to server logs, but returns a clean response to the client.
    """
    logger.exception(f"Unhandled exception processing {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error_type": "internal_server_error",
            "message": "An internal server error occurred. Please contact the administrator."
        }
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registers centralized exception handlers to the FastAPI app."""
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(AEGISException, aegis_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
