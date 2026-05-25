# Service-layer exceptions mapped by API handlers.


class ServiceError(Exception):
    pass


class NotFoundError(ServiceError):
    pass


class ConflictError(ServiceError):
    pass


class ValidationError(ServiceError):
    pass


class ServiceUnavailableError(ServiceError):
    pass
