class QuizError(Exception):
    """Base exception for the quiz application."""


class NetworkError(QuizError):
    """Raised for network-related issues (socket send/receive, timeouts)."""


class AuthError(QuizError):
    """Raised when authentication fails or is invalid."""


class DataFormatError(QuizError):
    """Raised for malformed or unexpected data (JSON parse/validation)."""


class ResourceLoadError(QuizError):
    """Raised when required resources (e.g., questions/users) fail to load."""



