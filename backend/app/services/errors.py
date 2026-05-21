"""Service-layer exceptions mapped by API handlers."""


class ServiceError(Exception):
    """Base service exception."""


class NotFoundError(ServiceError):
    """Raised when a requested entity does not exist."""


class ConflictError(ServiceError):
    """Raised when a unique or state conflict occurs."""


class ValidationError(ServiceError):
    """Raised when request data is invalid for the current workflow."""
