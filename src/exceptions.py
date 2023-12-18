# ==================================================================================================
#  Application exceptions
# ==================================================================================================

class InvalidCouchDBCredentialError(Exception):
    """Error obtaining CouchDB admin credentials."""
    ...

class InvalidAccesTokenKeyError(Exception):
    """Invalid access token key."""
    ...
