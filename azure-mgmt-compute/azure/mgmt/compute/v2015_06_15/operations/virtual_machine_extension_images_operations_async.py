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
from .virtual_machine_extension_images_operations import VirtualMachineExtensionImagesOperations as _VirtualMachineExtensionImagesOperations


class VirtualMachineExtensionImagesOperations(_VirtualMachineExtensionImagesOperations):

    async def get_async(
            self, location, publisher_name, type, version, *, custom_headers=None, raw=False, **operation_config):
        """Gets a virtual machine extension image.

        :param location: The name of a supported Azure region.
        :type location: str
        :param publisher_name:
        :type publisher_name: str
        :param type:
        :type type: str
        :param version:
        :type version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: VirtualMachineExtensionImage or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.compute.v2015_06_15.models.VirtualMachineExtensionImage or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get_async.metadata['url']
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str'),
            'publisherName': self._serialize.url("publisher_name", publisher_name, 'str'),
            'type': self._serialize.url("type", type, 'str'),
            'version': self._serialize.url("version", version, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        body_content = None
        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = await self._client.async_send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('VirtualMachineExtensionImage', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_async.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/publishers/{publisherName}/artifacttypes/vmextension/types/{type}/versions/{version}'}

    async def list_types_async(
            self, location, publisher_name, *, custom_headers=None, raw=False, **operation_config):
        """Gets a list of virtual machine extension image types.

        :param location: The name of a supported Azure region.
        :type location: str
        :param publisher_name:
        :type publisher_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.mgmt.compute.v2015_06_15.models.VirtualMachineExtensionImage]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.list_types_async.metadata['url']
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str'),
            'publisherName': self._serialize.url("publisher_name", publisher_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        body_content = None
        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = await self._client.async_send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('[VirtualMachineExtensionImage]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_types_async.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/publishers/{publisherName}/artifacttypes/vmextension/types'}

    async def list_versions_async(
            self, location, publisher_name, type, filter=None, top=None, orderby=None, *, custom_headers=None, raw=False, **operation_config):
        """Gets a list of virtual machine extension image versions.

        :param location: The name of a supported Azure region.
        :type location: str
        :param publisher_name:
        :type publisher_name: str
        :param type:
        :type type: str
        :param filter: The filter to apply on the operation.
        :type filter: str
        :param top:
        :type top: int
        :param orderby:
        :type orderby: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.mgmt.compute.v2015_06_15.models.VirtualMachineExtensionImage]
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.list_versions_async.metadata['url']
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str'),
            'publisherName': self._serialize.url("publisher_name", publisher_name, 'str'),
            'type': self._serialize.url("type", type, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if filter is not None:
            query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
        if top is not None:
            query_parameters['$top'] = self._serialize.query("top", top, 'int')
        if orderby is not None:
            query_parameters['$orderby'] = self._serialize.query("orderby", orderby, 'str')
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        body_content = None
        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = await self._client.async_send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('[VirtualMachineExtensionImage]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_versions_async.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/publishers/{publisherName}/artifacttypes/vmextension/types/{type}/versions'}
