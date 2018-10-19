import pkg_resources

from secretstore.module import SecretStore
from secretstore.session import (
    Session,
    SecretStoreSessionError
)

import secretstore.utils as utils

#__version__ = pkg_resources.get_distribution("secretstore").version
#__all__ = ["__version__", "SecretStore", "Session", "SecretStoreSessionError", "utils"]
__all__ = ["SecretStore", "Session", "SecretStoreSessionError", "utils"]
