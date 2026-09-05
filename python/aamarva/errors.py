class AamarvaError(Exception):
    pass

class AamarvaAPIError(AamarvaError):
    def __init__(self, message: str, status_code: int = None, code: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code

class AamarvaAuthenticationError(AamarvaAPIError):
    pass

class AamarvaRateLimitError(AamarvaAPIError):
    pass

class AamarvaTimeoutError(AamarvaError):
    pass

class AamarvaValidationError(AamarvaError):
    pass

class AamarvaConnectionError(AamarvaError):
    pass
