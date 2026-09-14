class AamarvaError(Exception):
    def __init__(self, message: str, code: str = "AAMARVA_ERROR", status_code: int = None, hint: str = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.hint = hint

    def __str__(self):
        res = f"{self.__class__.__name__} [{self.code}]: {self.message}"
        if self.status_code:
            res += f" (HTTP {self.status_code})"
        if self.hint:
            res += f"\nHint: {self.hint}"
        return res

class AamarvaAPIError(AamarvaError):
    def __init__(self, message: str, status_code: int = None, code: str = "API_ERROR", hint: str = None):
        super().__init__(message, code=code, status_code=status_code, hint=hint)

class AamarvaAuthenticationError(AamarvaAPIError):
    def __init__(self, message: str = "Authentication failed.", status_code: int = 401, code: str = "AUTH_INVALID"):
        super().__init__(message, status_code=status_code, code=code)

class AamarvaRateLimitError(AamarvaAPIError):
    def __init__(self, message: str = "Rate limit exceeded.", status_code: int = 429, code: str = "RATE_LIMIT_EXCEEDED"):
        super().__init__(message, status_code=status_code, code=code)

class AamarvaTimeoutError(AamarvaError):
    def __init__(self, message: str = "Request timed out.", code: str = "TIMEOUT"):
        super().__init__(message, code=code)

class AamarvaValidationError(AamarvaError):
    def __init__(self, message: str = "Validation failed.", code: str = "VALIDATION_FAILED"):
        super().__init__(message, code=code, status_code=400)

class AamarvaConnectionError(AamarvaError):
    def __init__(self, message: str = "Connection error.", code: str = "CONNECTION_ERROR"):
        super().__init__(message, code=code)
