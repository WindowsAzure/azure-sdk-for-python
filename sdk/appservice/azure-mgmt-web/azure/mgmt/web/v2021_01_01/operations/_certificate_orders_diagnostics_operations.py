# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class CertificateOrdersDiagnosticsOperations(object):
    """CertificateOrdersDiagnosticsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.web.v2021_01_01.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def list_app_service_certificate_order_detector_response(
        self,
        resource_group_name,  # type: str
        certificate_order_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.DetectorResponseCollection"]
        """Microsoft.CertificateRegistration to get the list of detectors for this RP.

        Description for Microsoft.CertificateRegistration to get the list of detectors for this RP.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param certificate_order_name: The certificate order name for which the response is needed.
        :type certificate_order_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DetectorResponseCollection or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.web.v2021_01_01.models.DetectorResponseCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DetectorResponseCollection"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-01-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_app_service_certificate_order_detector_response.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
                    'certificateOrderName': self._serialize.url("certificate_order_name", certificate_order_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('DetectorResponseCollection', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.DefaultErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_app_service_certificate_order_detector_response.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CertificateRegistration/certificateOrders/{certificateOrderName}/detectors'}  # type: ignore

    def get_app_service_certificate_order_detector_response(
        self,
        resource_group_name,  # type: str
        certificate_order_name,  # type: str
        detector_name,  # type: str
        start_time=None,  # type: Optional[datetime.datetime]
        end_time=None,  # type: Optional[datetime.datetime]
        time_grain=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.DetectorResponse"
        """Microsoft.CertificateRegistration call to get a detector response from App Lens.

        Description for Microsoft.CertificateRegistration call to get a detector response from App
        Lens.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param certificate_order_name: The certificate order name for which the response is needed.
        :type certificate_order_name: str
        :param detector_name: The detector name which needs to be run.
        :type detector_name: str
        :param start_time: The start time for detector response.
        :type start_time: ~datetime.datetime
        :param end_time: The end time for the detector response.
        :type end_time: ~datetime.datetime
        :param time_grain: The time grain for the detector response.
        :type time_grain: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DetectorResponse, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2021_01_01.models.DetectorResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DetectorResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-01-01"
        accept = "application/json"

        # Construct URL
        url = self.get_app_service_certificate_order_detector_response.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
            'certificateOrderName': self._serialize.url("certificate_order_name", certificate_order_name, 'str'),
            'detectorName': self._serialize.url("detector_name", detector_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if start_time is not None:
            query_parameters['startTime'] = self._serialize.query("start_time", start_time, 'iso-8601')
        if end_time is not None:
            query_parameters['endTime'] = self._serialize.query("end_time", end_time, 'iso-8601')
        if time_grain is not None:
            query_parameters['timeGrain'] = self._serialize.query("time_grain", time_grain, 'str', pattern=r'PT[1-9][0-9]+[SMH]')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.DefaultErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DetectorResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_app_service_certificate_order_detector_response.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CertificateRegistration/certificateOrders/{certificateOrderName}/detectors/{detectorName}'}  # type: ignore
