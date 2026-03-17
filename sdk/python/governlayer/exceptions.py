"""GovernLayer SDK exceptions."""


class GovernLayerError(Exception):
    """Base exception for GovernLayer SDK."""
    pass


class AuthError(GovernLayerError):
    """Authentication or authorization error."""
    pass


class APIError(GovernLayerError):
    """API request failed."""
    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class ValidationError(GovernLayerError):
    """Invalid request data."""
    pass
