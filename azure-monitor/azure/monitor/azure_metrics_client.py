# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from msrest.pipeline import ClientRawResponse
import uuid
from . import models


class AzureMetricsClientConfiguration(AzureConfiguration):
    """Configuration for AzureMetricsClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if not base_url:
            base_url = 'https://monitoring.azure.com'

        super(AzureMetricsClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-monitor/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials


class AzureMetricsClient(SDKClient):
    """Monitor Management Client

    :ivar config: Configuration for client.
    :vartype config: AzureMetricsClientConfiguration

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        self.config = AzureMetricsClientConfiguration(credentials, base_url)
        super(AzureMetricsClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-09-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)


    def azure_monitor_custom_metrics_ingestion_api(
            self, subscription_id, resource_group_name, resource_provider, resource_type_name, resource_name, content_type=None, content_length=None, time=None, data=None, custom_headers=None, raw=False, **operation_config):
        """Ingestion API used by Azure custom metrics
        Responsible of below operation
        1. Authorize the request
        2. Deserialize payload request body
        3. Perform validation of the payload
        4. Commits the payload for metrics ingestion.

        :param subscription_id: The azure subscription id
        :type subscription_id: str
        :param resource_group_name: The ARM resource group name
        :type resource_group_name: str
        :param resource_provider: The ARM resource provider name
        :type resource_provider: str
        :param resource_type_name: The ARM resource type name
        :type resource_type_name: str
        :param resource_name: The ARM resource name
        :type resource_name: str
        :param content_type: Supports application/json and
         application/x-ndjson
        :type content_type: str
        :param content_length: Content length of the payload
        :type content_length: int
        :param time: Gets or sets Time property (in ISO 8601 format)
        :type time: str
        :param data:
        :type data: ~azure.monitor.models.AzureMetricsData
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: AzureMetricsResult or ClientRawResponse if raw=true
        :rtype: ~azure.monitor.models.AzureMetricsResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`AzureMetricsResultException<azure.monitor.models.AzureMetricsResultException>`
        """
        body = models.AzureMetricsDocument(time=time, data=data)

        # Construct URL
        url = self.azure_monitor_custom_metrics_ingestion_api.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceProvider': self._serialize.url("resource_provider", resource_provider, 'str'),
            'resourceTypeName': self._serialize.url("resource_type_name", resource_type_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if content_type is not None:
            header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        if content_length is not None:
            header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'int')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(body, 'AzureMetricsDocument')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.AzureMetricsResultException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('AzureMetricsResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    azure_monitor_custom_metrics_ingestion_api.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProvider}/{resourceTypeName}/{resourceName}/metrics'}
