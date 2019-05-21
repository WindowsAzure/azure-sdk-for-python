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

import uuid
from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError

from .. import models


class HeatMapOperations(object):
    """HeatMapOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar heat_map_type: The type of HeatMap for the Traffic Manager profile. Constant value: "default".
    :ivar api_version: Client Api Version. Constant value: "2018-04-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.heat_map_type = "default"
        self.api_version = "2018-04-01"

        self.config = config

    def get(
            self, resource_group_name, profile_name, top_left=None, bot_right=None, custom_headers=None, raw=False, **operation_config):
        """Gets latest heatmap for Traffic Manager profile.

        :param resource_group_name: The name of the resource group containing
         the Traffic Manager endpoint.
        :type resource_group_name: str
        :param profile_name: The name of the Traffic Manager profile.
        :type profile_name: str
        :param top_left: The top left latitude,longitude pair of the
         rectangular viewport to query for.
        :type top_left: list[float]
        :param bot_right: The bottom right latitude,longitude pair of the
         rectangular viewport to query for.
        :type bot_right: list[float]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: HeatMapModel or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.trafficmanager.models.HeatMapModel or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str'),
            'heatMapType': self._serialize.url("self.heat_map_type", self.heat_map_type, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if top_left is not None:
            query_parameters['topLeft'] = self._serialize.query("top_left", top_left, '[float]', div=',', max_items=2, min_items=2)
        if bot_right is not None:
            query_parameters['botRight'] = self._serialize.query("bot_right", bot_right, '[float]', div=',', max_items=2, min_items=2)
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('HeatMapModel', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficmanagerprofiles/{profileName}/heatMaps/{heatMapType}'}
