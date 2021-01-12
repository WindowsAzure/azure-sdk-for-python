# pylint: disable=R0904
# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.tracing.decorator import distributed_trace

from ._phonenumber._generated._phone_numbers_client import PhoneNumbersClient as PhoneNumbersClientGen
from ._phonenumber._generated.models._models import PhoneNumberSearchResult
from ._shared.utils import parse_connection_str
from ._shared.policy import HMACCredentialsPolicy
from ._version import SDK_MONIKER

class PhoneNumbersClient(object):
    """Azure Communication Services Phone Number Management client.

    :param str endpoint:
        The endpoint url for Azure Communication Service resource.
    :param credential:
        The credentials with which to authenticate. The value is an account
        shared access key
    """
    def __init__(
            self,
            endpoint, # type: str
            credential, # type: str
            **kwargs # type: Any
    ):
        # type: (...) -> None
        try:
            if not endpoint.lower().startswith('http'):
                endpoint = "https://" + endpoint
        except AttributeError:
            raise ValueError("Account URL must be a string.")

        if not credential:
            raise ValueError(
                "You need to provide account shared key to authenticate.")

        self._endpoint = endpoint
        self._phone_numbers_client = PhoneNumbersClientGen(
            self._endpoint,
            authentication_policy=HMACCredentialsPolicy(endpoint, credential),
            sdk_moniker=SDK_MONIKER,
            **kwargs)

    @classmethod
    def from_connection_string(
            cls, conn_str,  # type: str
            **kwargs  # type: Any
    ):
        # type: (...) -> PhoneNumbersClient
        """Create PhoneNumbersClient from a Connection String.
        :param str conn_str:
            A connection string to an Azure Communication Service resource.
        :returns: Instance of PhoneNumbersClient.
        :rtype: ~azure.communication.PhoneNumbersClient
        """
        endpoint, access_key = parse_connection_str(conn_str)

        return cls(endpoint, access_key, **kwargs)

    @distributed_trace
    def begin_release_phone_number(
            self,
            phone_number,  # type: str
            **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller[None]
        """Begin releasing an acquired phone number.

        :param phone_number: The phone number id in E.164 format. The leading plus can be either + or
         encoded as %2B.
        :type phone_number: str
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError"""
        
        return self._phone_numbers_client.phone_numbers.begin_release_phone_number(
            phone_number,
            **kwargs
        )

    @distributed_trace
    def begin_search_available_phone_numbers(
        self,
        country_code,  # type: str
        phone_number_type,  # type: Union[str, "_models.PhoneNumberType"]
        assignment_type,  # type: Union[str, "_models.PhoneNumberAssignmentType"]
        capabilities,  # type: "_models.PhoneNumberCapabilitiesRequest"
        area_code=None,  # type: Optional[str]
        quantity=1,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller[PhoneNumberSearchResult]
        """Search for available phone numbers to purchase.

        Search for available phone numbers to purchase.

        :param country_code: The ISO 3166-2 country code.
        :type country_code: str
        :param phone_number_type: The phone number type.
        :type phone_number_type: str or ~azure.communication.administration.models.PhoneNumberType
        :param assignment_type: The phone number's assignment type.
        :type assignment_type: str or ~azure.communication.administration.models.PhoneNumberAssignmentType
        :param capabilities: The phone number's capabilities.
        :type capabilities: ~azure.communication.administration.models.PhoneNumberCapabilitiesRequest
        :param area_code: The desired area code.
        :type area_code: str
        :param quantity: The desired quantity of phone numbers.
        :type quantity: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[PhoneNumberSearchResult]
        :raises ~azure.core.exceptions.HttpResponseError:
        """

        self._phone_numbers_client.phone_numbers.begin_search_available_phone_numbers(
            country_code,
            phone_number_type,
            assignment_type,
            capabilities,
            area_code=area_code,
            quantity=quantity,
            **kwargs
        )

        return PhoneNumberSearchResult()

    @distributed_trace
    def begin_purchase_phone_numbers(
        self,
        search_id=None, # type: string
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller[None]
        """Begins purchasing phone numbers.
        :param search_id: The id of the search result to purchase.
        :type search_id: str
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError:
        """

        return self._phone_numbers_client.phone_numbers.begin_purchase_phone_numbers(
            search_id=search_id,
            **kwargs
        )

    @distributed_trace
    def begin_update_phone_number_capabilities(
        self,
        phone_number,  # type: str
        sms="none",  # type: Optional[Union[str, "_models.PhoneNumberCapabilityValue"]]
        calling="none",  # type: Optional[Union[str, "_models.PhoneNumberCapabilityValue"]]
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller["_models.AcquiredPhoneNumber"]
        """Begin update capabilities of an acquired phone number.

        :param phone_number: The phone number id in E.164 format. The leading plus can be either + or
         encoded as %2B.
        :type phone_number: str
        :param sms: Available Sms capabilities.
        :type sms: str or ~azure.communication.administration.models.PhoneNumberCapabilityValue
        :param calling: Available Calling capabilities.
        :type calling: str or ~azure.communication.administration.models.PhoneNumberCapabilityValue
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either AcquiredPhoneNumber or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[~azure.communication.administration.models.AcquiredPhoneNumber]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        self._phone_numbers_client.phone_numbers.begin_update_phone_number_capabilities(
            phone_number,
            sms=sms,
            calling=callable,
            **kwargs
        )


    @distributed_trace
    def get_phone_number(
        self,
        phone_number,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.AcquiredPhoneNumber"
        """Gets information about an acquired phone number.

        Gets information about an acquired phone number.

        :param phone_number: The phone number id in E.164 format. The leading plus can be either + or
         encoded as %2B.
        :type phone_number: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AcquiredPhoneNumber, or the result of cls(response)
        :rtype: ~azure.communication.administration.models.AcquiredPhoneNumber
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        return self._phone_numbers_client.phone_numbers.get_phone_number(
            phone_number,
            **kwargs
        )

    @distributed_trace
    def list_phone_numbers(
        self,
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.AcquiredPhoneNumbers"]
        """Lists acquired phone numbers.

        Lists acquired phone numbers.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either AcquiredPhoneNumbers or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.communication.administration.models.AcquiredPhoneNumbers]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        return self._phone_numbers_client.phone_numbers.list_phone_numbers(
            **kwargs
        )

    @distributed_trace
    def update_phone_number(
        self,
        phone_number,  # type: str
        callback_uri=None,  # type: Optional[str]
        application_id=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.AcquiredPhoneNumber"
        """Update an acquired phone number.

        Update an acquired phone number.

        :param phone_number: The phone number id in E.164 format. The leading plus can be either + or
         encoded as %2B.
        :type phone_number: str
        :param callback_uri: The webhook for receiving incoming events.
        :type callback_uri: str
        :param application_id: The application id the number has been assigned to.
        :type application_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AcquiredPhoneNumber, or the result of cls(response)
        :rtype: ~azure.communication.administration.models.AcquiredPhoneNumber
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        return self._phone_numbers_client.phone_numbers.update_phone_number(
            phone_number,
            callback_uri=callback_uri,
            application_id=application_id,
            **kwargs
        )
