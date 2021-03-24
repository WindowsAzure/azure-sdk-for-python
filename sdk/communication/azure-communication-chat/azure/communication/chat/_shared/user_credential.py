# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from threading import Lock, Condition
from datetime import timedelta
from typing import ( # pylint: disable=unused-import
    cast,
    Tuple,
)

from .utils import get_current_utc_as_int
from .user_token_refresh_options import CommunicationTokenRefreshOptions


class CommunicationTokenCredential(object):
    """Credential type used for authenticating to an Azure Communication service.
    :param str token: The token used to authenticate to an Azure Communication service
    :keyword token_refresher: The token refresher to provide capacity to fetch fresh token
    :raises: TypeError
    """

    _ON_DEMAND_REFRESHING_INTERVAL_MINUTES = 2

    def __init__(self,
                 token,  # type: str
                 **kwargs
                 ):
        token_refresher = kwargs.pop('token_refresher', None)
        communication_token_refresh_options = CommunicationTokenRefreshOptions(token=token,
                                                                               token_refresher=token_refresher)
        self._token = communication_token_refresh_options.get_token()
        self._token_refresher = communication_token_refresh_options.get_token_refresher()
        self._lock = Condition(Lock())
        self._some_thread_refreshing = False

    def get_token(self, *scopes, **kwargs):  # pylint: disable=unused-argument
        # type (*str, **Any) -> AccessToken
        """The value of the configured token.
        :rtype: ~azure.core.credentials.AccessToken
        """

        if not self._token_refresher or not self._token_expiring():
            return self._token

        should_this_thread_refresh = False

        with self._lock:
            while self._token_expiring():
                if self._some_thread_refreshing:
                    if self._is_currenttoken_valid():
                        return self._token

                    self._wait_till_inprogress_thread_finish_refreshing()
                else:
                    should_this_thread_refresh = True
                    self._some_thread_refreshing = True
                    break

        if should_this_thread_refresh:
            try:
                newtoken = self._token_refresher()  # pylint:disable=not-callable

                with self._lock:
                    self._token = newtoken
                    self._some_thread_refreshing = False
                    self._lock.notify_all()
            except:
                with self._lock:
                    self._some_thread_refreshing = False
                    self._lock.notify_all()

                raise
        return self._token

    def _wait_till_inprogress_thread_finish_refreshing(self):
        self._lock.release()
        self._lock.acquire()

    def _token_expiring(self):
        return self._token.expires_on - get_current_utc_as_int() <\
            timedelta(minutes=self._ON_DEMAND_REFRESHING_INTERVAL_MINUTES).total_seconds()

    def _is_currenttoken_valid(self):
        return get_current_utc_as_int() < self._token.expires_on
