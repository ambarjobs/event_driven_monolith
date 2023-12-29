# ==================================================================================================
#  Application exceptions
# ==================================================================================================


# --------------------------------------------------------------------------------------------------
#   Database
# --------------------------------------------------------------------------------------------------
class InvalidCouchDBCredentialError(Exception):
    """Error obtaining CouchDB admin credentials."""
    ...


# --------------------------------------------------------------------------------------------------
#   Authentication
# --------------------------------------------------------------------------------------------------
class InvalidAccesTokenKeyError(Exception):
    """Invalid access token key."""
    ...


# --------------------------------------------------------------------------------------------------
#   PubSub
# --------------------------------------------------------------------------------------------------
class MessagePublishingConfirmationError(Exception):
    """The message sending through PubSub could not be confirmed."""
    ...


class ProducerNotRegisteredError(Exception):
    """The producer was not found in the producers register map."""
    ...


class ConsumerServiceNotFoundError(Exception):
    """The consumer service function could not be found."""
    ...
