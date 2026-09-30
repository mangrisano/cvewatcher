class OidcError(Exception):
    """A failed sign-in; ``code`` is shown to the user, never provider details."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
