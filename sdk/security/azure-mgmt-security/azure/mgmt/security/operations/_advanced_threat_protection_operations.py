# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class AdvancedThreatProtectionOperations(object):
    """AdvancedThreatProtectionOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.security.models
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

    def get(
        self,
        resource_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.AdvancedThreatProtectionSetting"
        """Gets the Advanced Threat Protection settings for the specified resource.

        :param resource_id: The identifier of the resource.
        :type resource_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AdvancedThreatProtectionSetting, or the result of cls(response)
        :rtype: ~azure.mgmt.security.models.AdvancedThreatProtectionSetting
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AdvancedThreatProtectionSetting"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"
        setting_name = "current"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceId': self._serialize.url("resource_id", resource_id, 'str', skip_quote=True),
            'settingName': self._serialize.url("setting_name", setting_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('AdvancedThreatProtectionSetting', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/{resourceId}/providers/Microsoft.Security/advancedThreatProtectionSettings/{settingName}'}  # type: ignore

    def create(
        self,
        resource_id,  # type: str
        advanced_threat_protection_setting,  # type: "_models.AdvancedThreatProtectionSetting"
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.AdvancedThreatProtectionSetting"
        """Creates or updates the Advanced Threat Protection settings on a specified resource.

        :param resource_id: The identifier of the resource.
        :type resource_id: str
        :param advanced_threat_protection_setting: Advanced Threat Protection Settings.
        :type advanced_threat_protection_setting: ~azure.mgmt.security.models.AdvancedThreatProtectionSetting
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AdvancedThreatProtectionSetting, or the result of cls(response)
        :rtype: ~azure.mgmt.security.models.AdvancedThreatProtectionSetting
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AdvancedThreatProtectionSetting"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"
        setting_name = "current"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceId': self._serialize.url("resource_id", resource_id, 'str', skip_quote=True),
            'settingName': self._serialize.url("setting_name", setting_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(advanced_threat_protection_setting, 'AdvancedThreatProtectionSetting')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('AdvancedThreatProtectionSetting', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/{resourceId}/providers/Microsoft.Security/advancedThreatProtectionSettings/{settingName}'}  # type: ignore
