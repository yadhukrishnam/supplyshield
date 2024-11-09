class ImageNotFoundException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.is_invalid_arch = "Error: no child with platform" in message


class SCADependencyException(Exception):
    """
    This exception means some data was expected to be present in the database as a dependency,
    typically created by sbom results and was not found.
    """

    ...
