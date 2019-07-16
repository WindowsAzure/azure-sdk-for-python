# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import six

from uamqp import constants, errors, compat


_NO_RETRY_ERRORS = (
    b"com.microsoft:argument-out-of-range",
    b"com.microsoft:entity-disabled",
    b"com.microsoft:auth-failed",
    b"com.microsoft:precondition-failed",
    b"com.microsoft:argument-error"
)


def _error_handler(error):
    """
    Called internally when an event has failed to send so we
    can parse the error to determine whether we should attempt
    to retry sending the event again.
    Returns the action to take according to error type.

    :param error: The error received in the send attempt.
    :type error: Exception
    :rtype: ~uamqp.errors.ErrorAction
    """
    if error.condition == b'com.microsoft:server-busy':
        return errors.ErrorAction(retry=True, backoff=4)
    if error.condition == b'com.microsoft:timeout':
        return errors.ErrorAction(retry=True, backoff=2)
    if error.condition == b'com.microsoft:operation-cancelled':
        return errors.ErrorAction(retry=True)
    if error.condition == b"com.microsoft:container-close":
        return errors.ErrorAction(retry=True, backoff=4)
    if error.condition in _NO_RETRY_ERRORS:
        return errors.ErrorAction(retry=False)
    return errors.ErrorAction(retry=True)


class EventHubError(Exception):
    """
    Represents an error happened in the client.

    :ivar message: The error message.
    :vartype message: str
    :ivar error: The error condition, if available.
    :vartype error: str
    :ivar details: The error details, if included in the
     service response.
    :vartype details: dict[str, str]
    """

    def __init__(self, message, details=None):
        self.error = None
        self.message = message
        self.details = details
        if details and isinstance(details, Exception):
            try:
                condition = details.condition.value.decode('UTF-8')
            except AttributeError:
                try:
                    condition = details.condition.decode('UTF-8')
                except AttributeError:
                    condition = None
            if condition:
                _, _, self.error = condition.partition(':')
                self.message += "\nError: {}".format(self.error)
            try:
                self._parse_error(details.description)
                for detail in self.details:
                    self.message += "\n{}".format(detail)
            except:  # pylint: disable=bare-except
                self.message += "\n{}".format(details)
        super(EventHubError, self).__init__(self.message)

    def _parse_error(self, error_list):
        details = []
        self.message = error_list if isinstance(error_list, six.text_type) else error_list.decode('UTF-8')
        details_index = self.message.find(" Reference:")
        if details_index >= 0:
            details_msg = self.message[details_index + 1:]
            self.message = self.message[0:details_index]

            tracking_index = details_msg.index(", TrackingId:")
            system_index = details_msg.index(", SystemTracker:")
            timestamp_index = details_msg.index(", Timestamp:")
            details.append(details_msg[:tracking_index])
            details.append(details_msg[tracking_index + 2: system_index])
            details.append(details_msg[system_index + 2: timestamp_index])
            details.append(details_msg[timestamp_index + 2:])
            self.details = details


class ConnectionLostError(EventHubError):
    """Connection to event hub is lost. SDK will retry. So this shouldn't happen.

    """
    pass


class ConnectError(EventHubError):
    """Fail to connect to event hubs

    """
    pass


class AuthenticationError(ConnectError):
    """Fail to connect to event hubs because of authentication problem


    """
    pass


class EventDataError(EventHubError):
    """Problematic event data so the send will fail at client side

    """
    pass


class EventDataSendError(EventHubError):
    """Service returns error while an event data is being sent

    """
    pass


def _handle_exception(exception, retry_count, max_retries, closable, log):
    if isinstance(exception, KeyboardInterrupt):
        log.info("EventHubConsumer stops due to keyboard interrupt")
        closable.close()
        raise
    elif isinstance(exception, (
            errors.MessageAccepted,
            errors.MessageAlreadySettled,
            errors.MessageModified,
            errors.MessageRejected,
            errors.MessageReleased,
            errors.MessageContentTooLarge)
            ):
        log.error("Event data error (%r)", exception)
        error = EventDataError(str(exception), exception)
        closable.close(exception)
        raise error
    elif isinstance(exception, errors.MessageException):
        log.error("Event data send error (%r)", exception)
        error = EventDataSendError(str(exception), exception)
        closable.close(exception)
        raise error
    elif retry_count >= max_retries:
        log.info("EventHubConsumer has an error and has exhausted retrying. (%r)", exception)
        if isinstance(exception, errors.AuthenticationException):
            log.info("EventHubConsumer authentication failed. Shutting down.")
            error = AuthenticationError(str(exception), exception)
        elif isinstance(exception, errors.VendorLinkDetach):
            log.info("EventHubConsumer link detached. Shutting down.")
            error = ConnectError(str(exception), exception)
        elif isinstance(exception, errors.LinkDetach):
            log.info("EventHubConsumer link detached. Shutting down.")
            error = ConnectionLostError(str(exception), exception)
        elif isinstance(exception, errors.ConnectionClose):
            log.info("EventHubConsumer connection closed. Shutting down.")
            error = ConnectionLostError(str(exception), exception)
        elif isinstance(exception, errors.MessageHandlerError):
            log.info("EventHubConsumer detached. Shutting down.")
            error = ConnectionLostError(str(exception), exception)
        elif isinstance(exception, errors.AMQPConnectionError):
            log.info("EventHubConsumer connection lost. Shutting down.")
            error_type = AuthenticationError if str(exception).startswith("Unable to open authentication session") \
                else ConnectError
            error = error_type(str(exception), exception)
        elif isinstance(exception, compat.TimeoutException):
            log.info("EventHubConsumer timed out. Shutting down.")
            error = ConnectionLostError(str(exception), exception)
        else:
            log.error("Unexpected error occurred (%r). Shutting down.", exception)
            error = EventHubError("Receive failed: {}".format(exception), exception)
        closable.close(exception=error)
        raise error
    else:
        log.info("EventHubConsumer has an exception (%r). Retrying...", exception)
        if isinstance(exception, errors.AuthenticationException):
            closable._close_connection()
        elif isinstance(exception, errors.LinkRedirect):
            log.info("EventHubConsumer link redirected. Redirecting...")
            redirect = exception
            closable._redirect(redirect)
        elif isinstance(exception, errors.LinkDetach):
            closable._close_handler()
        elif isinstance(exception, errors.ConnectionClose):
            closable._close_connection()
        elif isinstance(exception, errors.MessageHandlerError):
            closable._close_handler()
        elif isinstance(exception, errors.AMQPConnectionError):
            closable._close_connection()
        elif isinstance(exception, compat.TimeoutException):
            pass  # Timeout doesn't need to recreate link or exception
        else:
            closable._close_connection()
