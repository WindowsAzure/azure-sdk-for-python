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
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class GalleryApplicationVersionsOperations(object):
    """GalleryApplicationVersionsOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2019-07-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-07-01"

        self.config = config


    def _create_or_update_initial(
            self, resource_group_name, gallery_name, gallery_application_name, gallery_application_version_name, gallery_application_version, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryApplicationName': self._serialize.url("gallery_application_name", gallery_application_name, 'str'),
            'galleryApplicationVersionName': self._serialize.url("gallery_application_version_name", gallery_application_version_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(gallery_application_version, 'GalleryApplicationVersion')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('GalleryApplicationVersion', response)
        if response.status_code == 201:
            deserialized = self._deserialize('GalleryApplicationVersion', response)
        if response.status_code == 202:
            deserialized = self._deserialize('GalleryApplicationVersion', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, resource_group_name, gallery_name, gallery_application_name, gallery_application_version_name, gallery_application_version, custom_headers=None, raw=False, polling=True, **operation_config):
        """Create or update a gallery Application Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Application Gallery in
         which the Application Definition resides.
        :type gallery_name: str
        :param gallery_application_name: The name of the gallery Application
         Definition in which the Application Version is to be created.
        :type gallery_application_name: str
        :param gallery_application_version_name: The name of the gallery
         Application Version to be created. Needs to follow semantic version
         name pattern: The allowed characters are digit and period. Digits must
         be within the range of a 32-bit integer. Format:
         <MajorVersion>.<MinorVersion>.<Patch>
        :type gallery_application_version_name: str
        :param gallery_application_version: Parameters supplied to the create
         or update gallery Application Version operation.
        :type gallery_application_version:
         ~azure.mgmt.compute.v2019_07_01.models.GalleryApplicationVersion
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns
         GalleryApplicationVersion or
         ClientRawResponse<GalleryApplicationVersion> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.compute.v2019_07_01.models.GalleryApplicationVersion]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.compute.v2019_07_01.models.GalleryApplicationVersion]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._create_or_update_initial(
            resource_group_name=resource_group_name,
            gallery_name=gallery_name,
            gallery_application_name=gallery_application_name,
            gallery_application_version_name=gallery_application_version_name,
            gallery_application_version=gallery_application_version,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('GalleryApplicationVersion', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/applications/{galleryApplicationName}/versions/{galleryApplicationVersionName}'}

    def get(
            self, resource_group_name, gallery_name, gallery_application_name, gallery_application_version_name, expand=None, custom_headers=None, raw=False, **operation_config):
        """Retrieves information about a gallery Application Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Application Gallery in
         which the Application Definition resides.
        :type gallery_name: str
        :param gallery_application_name: The name of the gallery Application
         Definition in which the Application Version resides.
        :type gallery_application_name: str
        :param gallery_application_version_name: The name of the gallery
         Application Version to be retrieved.
        :type gallery_application_version_name: str
        :param expand: The expand expression to apply on the operation.
         Possible values include: 'ReplicationStatus'
        :type expand: str or
         ~azure.mgmt.compute.v2019_07_01.models.ReplicationStatusTypes
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: GalleryApplicationVersion or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.compute.v2019_07_01.models.GalleryApplicationVersion or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryApplicationName': self._serialize.url("gallery_application_name", gallery_application_name, 'str'),
            'galleryApplicationVersionName': self._serialize.url("gallery_application_version_name", gallery_application_version_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
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
            deserialized = self._deserialize('GalleryApplicationVersion', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/applications/{galleryApplicationName}/versions/{galleryApplicationVersionName}'}


    def _delete_initial(
            self, resource_group_name, gallery_name, gallery_application_name, gallery_application_version_name, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryApplicationName': self._serialize.url("gallery_application_name", gallery_application_name, 'str'),
            'galleryApplicationVersionName': self._serialize.url("gallery_application_version_name", gallery_application_version_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def delete(
            self, resource_group_name, gallery_name, gallery_application_name, gallery_application_version_name, custom_headers=None, raw=False, polling=True, **operation_config):
        """Delete a gallery Application Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Application Gallery in
         which the Application Definition resides.
        :type gallery_name: str
        :param gallery_application_name: The name of the gallery Application
         Definition in which the Application Version resides.
        :type gallery_application_name: str
        :param gallery_application_version_name: The name of the gallery
         Application Version to be deleted.
        :type gallery_application_version_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns None or
         ClientRawResponse<None> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[None]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._delete_initial(
            resource_group_name=resource_group_name,
            gallery_name=gallery_name,
            gallery_application_name=gallery_application_name,
            gallery_application_version_name=gallery_application_version_name,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            if raw:
                client_raw_response = ClientRawResponse(None, response)
                return client_raw_response

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/applications/{galleryApplicationName}/versions/{galleryApplicationVersionName}'}

    def list_by_gallery_application(
            self, resource_group_name, gallery_name, gallery_application_name, custom_headers=None, raw=False, **operation_config):
        """List gallery Application Versions in a gallery Application Definition.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Application Gallery in
         which the Application Definition resides.
        :type gallery_name: str
        :param gallery_application_name: The name of the Shared Application
         Gallery Application Definition from which the Application Versions are
         to be listed.
        :type gallery_application_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of GalleryApplicationVersion
        :rtype:
         ~azure.mgmt.compute.v2019_07_01.models.GalleryApplicationVersionPaged[~azure.mgmt.compute.v2019_07_01.models.GalleryApplicationVersion]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_gallery_application.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
                    'galleryApplicationName': self._serialize.url("gallery_application_name", gallery_application_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.GalleryApplicationVersionPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_by_gallery_application.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/applications/{galleryApplicationName}/versions'}
