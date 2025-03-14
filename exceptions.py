class PrettyReconError(Exception):
    """Base exception for PrettyRecon errors"""
    pass

class AuthenticationError(PrettyReconError):
    """Raised when authentication fails"""
    pass

class ScanError(PrettyReconError):
    """Raised when a scan operation fails"""
    pass

class OutputError(PrettyReconError):
    """Raised when there's an error saving output"""
    pass

class ValidationError(PrettyReconError):
    """Raised when input validation fails"""
    pass 