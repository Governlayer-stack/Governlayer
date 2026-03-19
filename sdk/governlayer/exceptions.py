"""GovernLayer SDK — custom exceptions."""


class GovernLayerError(Exception):
    """Base exception for all GovernLayer SDK errors.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code from the API, if applicable.
        response_body: Raw response body from the API, if available.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: dict | None = None,
    ):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(message)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, status_code={self.status_code})"


class AuthenticationError(GovernLayerError):
    """Raised when the API key or JWT token is invalid or missing (HTTP 401)."""


class AuthorizationError(GovernLayerError):
    """Raised when the authenticated identity lacks permission for the requested action (HTTP 403)."""


class NotFoundError(GovernLayerError):
    """Raised when the requested resource does not exist (HTTP 404)."""


class ValidationError(GovernLayerError):
    """Raised when the request payload fails server-side validation (HTTP 422)."""


class RateLimitError(GovernLayerError):
    """Raised when the API rate limit has been exceeded (HTTP 429).

    Attributes:
        retry_after: Seconds to wait before retrying, if provided by the server.
    """

    def __init__(
        self,
        message: str,
        status_code: int = 429,
        response_body: dict | None = None,
        retry_after: float | None = None,
    ):
        super().__init__(message, status_code, response_body)
        self.retry_after = retry_after


class ServerError(GovernLayerError):
    """Raised when the API returns an internal server error (HTTP 5xx)."""


class ConnectionError(GovernLayerError):
    """Raised when the SDK cannot reach the GovernLayer API."""


class TimeoutError(GovernLayerError):
    """Raised when a request to the GovernLayer API times out."""
