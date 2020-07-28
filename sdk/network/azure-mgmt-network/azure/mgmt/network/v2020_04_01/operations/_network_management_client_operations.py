# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.core.polling import LROPoller, NoPolling, PollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.arm_polling import ARMPolling

from .. import models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar, Union

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class NetworkManagementClientOperationsMixin(object):

    def _put_bastion_shareable_link_initial(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        bsl_request,  # type: "models.BastionShareableLinkListRequest"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.BastionShareableLinkListResult"
        cls = kwargs.pop('cls', None)  # type: ClsType["models.BastionShareableLinkListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self._put_bastion_shareable_link_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'bastionHostName': self._serialize.url("bastion_host_name", bastion_host_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(bsl_request, 'BastionShareableLinkListRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('BastionShareableLinkListResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _put_bastion_shareable_link_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/createShareableLinks'}  # type: ignore

    def begin_put_bastion_shareable_link(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        bsl_request,  # type: "models.BastionShareableLinkListRequest"
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller
        """Creates a Bastion Shareable Links for all the VMs specified in the request.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param bastion_host_name: The name of the Bastion Host.
        :type bastion_host_name: str
        :param bsl_request: Post request for all the Bastion Shareable Link endpoints.
        :type bsl_request: ~azure.mgmt.network.v2020_04_01.models.BastionShareableLinkListRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either BastionShareableLinkListResult or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[~azure.mgmt.network.v2020_04_01.models.BastionShareableLinkListResult]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.BastionShareableLinkListResult"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._put_bastion_shareable_link_initial(
                resource_group_name=resource_group_name,
                bastion_host_name=bastion_host_name,
                bsl_request=bsl_request,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('BastionShareableLinkListResult', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = ARMPolling(lro_delay, lro_options={'final-state-via': 'location'},  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_put_bastion_shareable_link.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/createShareableLinks'}  # type: ignore

    def _delete_bastion_shareable_link_initial(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        bsl_request,  # type: "models.BastionShareableLinkListRequest"
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self._delete_bastion_shareable_link_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'bastionHostName': self._serialize.url("bastion_host_name", bastion_host_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(bsl_request, 'BastionShareableLinkListRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    _delete_bastion_shareable_link_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/deleteShareableLinks'}  # type: ignore

    def begin_delete_bastion_shareable_link(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        bsl_request,  # type: "models.BastionShareableLinkListRequest"
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller
        """Deletes the Bastion Shareable Links for all the VMs specified in the request.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param bastion_host_name: The name of the Bastion Host.
        :type bastion_host_name: str
        :param bsl_request: Post request for all the Bastion Shareable Link endpoints.
        :type bsl_request: ~azure.mgmt.network.v2020_04_01.models.BastionShareableLinkListRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._delete_bastion_shareable_link_initial(
                resource_group_name=resource_group_name,
                bastion_host_name=bastion_host_name,
                bsl_request=bsl_request,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        if polling is True: polling_method = ARMPolling(lro_delay, lro_options={'final-state-via': 'location'},  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_delete_bastion_shareable_link.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/deleteShareableLinks'}  # type: ignore

    def get_bastion_shareable_link(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        bsl_request,  # type: "models.BastionShareableLinkListRequest"
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.BastionShareableLinkListResult"]
        """Return the Bastion Shareable Links for all the VMs specified in the request.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param bastion_host_name: The name of the Bastion Host.
        :type bastion_host_name: str
        :param bsl_request: Post request for all the Bastion Shareable Link endpoints.
        :type bsl_request: ~azure.mgmt.network.v2020_04_01.models.BastionShareableLinkListRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BastionShareableLinkListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.network.v2020_04_01.models.BastionShareableLinkListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.BastionShareableLinkListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"
        content_type = "application/json"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.get_bastion_shareable_link.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'bastionHostName': self._serialize.url("bastion_host_name", bastion_host_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            body_content_kwargs = {}  # type: Dict[str, Any]
            body_content = self._serialize.body(bsl_request, 'BastionShareableLinkListRequest')
            body_content_kwargs['content'] = body_content
            request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('BastionShareableLinkListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    get_bastion_shareable_link.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/getShareableLinks'}  # type: ignore

    def _get_active_sessions_initial(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.BastionActiveSessionListResult"
        cls = kwargs.pop('cls', None)  # type: ClsType["models.BastionActiveSessionListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"

        # Construct URL
        url = self._get_active_sessions_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'bastionHostName': self._serialize.url("bastion_host_name", bastion_host_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('BastionActiveSessionListResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _get_active_sessions_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/getActiveSessions'}  # type: ignore

    def begin_get_active_sessions(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller
        """Returns the list of currently active sessions on the Bastion.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param bastion_host_name: The name of the Bastion Host.
        :type bastion_host_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either BastionActiveSessionListResult or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[~azure.mgmt.network.v2020_04_01.models.BastionActiveSessionListResult]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.BastionActiveSessionListResult"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._get_active_sessions_initial(
                resource_group_name=resource_group_name,
                bastion_host_name=bastion_host_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('BastionActiveSessionListResult', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = ARMPolling(lro_delay, lro_options={'final-state-via': 'location'},  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_get_active_sessions.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/getActiveSessions'}  # type: ignore

    def disconnect_active_sessions(
        self,
        resource_group_name,  # type: str
        bastion_host_name,  # type: str
        session_ids,  # type: "models.SessionIds"
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.BastionSessionDeleteResult"]
        """Returns the list of currently active sessions on the Bastion.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param bastion_host_name: The name of the Bastion Host.
        :type bastion_host_name: str
        :param session_ids: The list of sessionids to disconnect.
        :type session_ids: ~azure.mgmt.network.v2020_04_01.models.SessionIds
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BastionSessionDeleteResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.network.v2020_04_01.models.BastionSessionDeleteResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.BastionSessionDeleteResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"
        content_type = "application/json"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.disconnect_active_sessions.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'bastionHostName': self._serialize.url("bastion_host_name", bastion_host_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            body_content_kwargs = {}  # type: Dict[str, Any]
            body_content = self._serialize.body(session_ids, 'SessionIds')
            body_content_kwargs['content'] = body_content
            request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('BastionSessionDeleteResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    disconnect_active_sessions.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/bastionHosts/{bastionHostName}/disconnectActiveSessions'}  # type: ignore

    def check_dns_name_availability(
        self,
        location,  # type: str
        domain_name_label,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.DnsNameAvailabilityResult"
        """Checks whether a domain name in the cloudapp.azure.com zone is available for use.

        :param location: The location of the domain name.
        :type location: str
        :param domain_name_label: The domain name to be verified. It must conform to the following
         regular expression: ^[a-z][a-z0-9-]{1,61}[a-z0-9]$.
        :type domain_name_label: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DnsNameAvailabilityResult, or the result of cls(response)
        :rtype: ~azure.mgmt.network.v2020_04_01.models.DnsNameAvailabilityResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DnsNameAvailabilityResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"

        # Construct URL
        url = self.check_dns_name_availability.metadata['url']  # type: ignore
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['domainNameLabel'] = self._serialize.query("domain_name_label", domain_name_label, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DnsNameAvailabilityResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    check_dns_name_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Network/locations/{location}/CheckDnsNameAvailability'}  # type: ignore

    def supported_security_providers(
        self,
        resource_group_name,  # type: str
        virtual_wan_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.VirtualWanSecurityProviders"
        """Gives the supported security providers for the virtual wan.

        :param resource_group_name: The resource group name.
        :type resource_group_name: str
        :param virtual_wan_name: The name of the VirtualWAN for which supported security providers are
         needed.
        :type virtual_wan_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: VirtualWanSecurityProviders, or the result of cls(response)
        :rtype: ~azure.mgmt.network.v2020_04_01.models.VirtualWanSecurityProviders
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.VirtualWanSecurityProviders"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"

        # Construct URL
        url = self.supported_security_providers.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'virtualWANName': self._serialize.url("virtual_wan_name", virtual_wan_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('VirtualWanSecurityProviders', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    supported_security_providers.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualWans/{virtualWANName}/supportedSecurityProviders'}  # type: ignore

    def _generatevirtualwanvpnserverconfigurationvpnprofile_initial(
        self,
        resource_group_name,  # type: str
        virtual_wan_name,  # type: str
        vpn_client_params,  # type: "models.VirtualWanVpnProfileParameters"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.VpnProfileResponse"
        cls = kwargs.pop('cls', None)  # type: ClsType["models.VpnProfileResponse"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-04-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self._generatevirtualwanvpnserverconfigurationvpnprofile_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'virtualWANName': self._serialize.url("virtual_wan_name", virtual_wan_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(vpn_client_params, 'VirtualWanVpnProfileParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('VpnProfileResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _generatevirtualwanvpnserverconfigurationvpnprofile_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualWans/{virtualWANName}/GenerateVpnProfile'}  # type: ignore

    def begin_generatevirtualwanvpnserverconfigurationvpnprofile(
        self,
        resource_group_name,  # type: str
        virtual_wan_name,  # type: str
        vpn_client_params,  # type: "models.VirtualWanVpnProfileParameters"
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller
        """Generates a unique VPN profile for P2S clients for VirtualWan and associated
    VpnServerConfiguration combination in the specified resource group.

        :param resource_group_name: The resource group name.
        :type resource_group_name: str
        :param virtual_wan_name: The name of the VirtualWAN whose associated VpnServerConfigurations is
     needed.
        :type virtual_wan_name: str
        :param vpn_client_params: Parameters supplied to the generate VirtualWan VPN profile generation
     operation.
        :type vpn_client_params: ~azure.mgmt.network.v2020_04_01.models.VirtualWanVpnProfileParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either VpnProfileResponse or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[~azure.mgmt.network.v2020_04_01.models.VpnProfileResponse]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.VpnProfileResponse"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._generatevirtualwanvpnserverconfigurationvpnprofile_initial(
                resource_group_name=resource_group_name,
                virtual_wan_name=virtual_wan_name,
                vpn_client_params=vpn_client_params,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('VpnProfileResponse', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = ARMPolling(lro_delay, lro_options={'final-state-via': 'location'},  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_generatevirtualwanvpnserverconfigurationvpnprofile.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualWans/{virtualWANName}/GenerateVpnProfile'}  # type: ignore
