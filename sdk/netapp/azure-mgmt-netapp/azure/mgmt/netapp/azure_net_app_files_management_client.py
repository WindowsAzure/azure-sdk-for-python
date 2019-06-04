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
from msrestazure.azure_exceptions import CloudError
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling
import uuid
from .operations.operations import Operations
from .operations.accounts_operations import AccountsOperations
from .operations.pools_operations import PoolsOperations
from .operations.volumes_operations import VolumesOperations
from .operations.mount_targets_operations import MountTargetsOperations
from .operations.snapshots_operations import SnapshotsOperations
from . import models


class AzureNetAppFilesManagementClientConfiguration(AzureConfiguration):
    """Configuration for AzureNetAppFilesManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(AzureNetAppFilesManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-netapp/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class AzureNetAppFilesManagementClient(SDKClient):
    """Microsoft NetApp Azure Resource Provider specification

    :ivar config: Configuration for client.
    :vartype config: AzureNetAppFilesManagementClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.netapp.operations.Operations
    :ivar accounts: Accounts operations
    :vartype accounts: azure.mgmt.netapp.operations.AccountsOperations
    :ivar pools: Pools operations
    :vartype pools: azure.mgmt.netapp.operations.PoolsOperations
    :ivar volumes: Volumes operations
    :vartype volumes: azure.mgmt.netapp.operations.VolumesOperations
    :ivar mount_targets: MountTargets operations
    :vartype mount_targets: azure.mgmt.netapp.operations.MountTargetsOperations
    :ivar snapshots: Snapshots operations
    :vartype snapshots: azure.mgmt.netapp.operations.SnapshotsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = AzureNetAppFilesManagementClientConfiguration(credentials, subscription_id, base_url)
        super(AzureNetAppFilesManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-05-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.accounts = AccountsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.pools = PoolsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.volumes = VolumesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mount_targets = MountTargetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.snapshots = SnapshotsOperations(
            self._client, self.config, self._serialize, self._deserialize)

    def check_name_availability(
            self, body, location, custom_headers=None, raw=False, **operation_config):
        """Check resource name availability.

        Check if a resource name is available.

        :param body: Name availability request.
        :type body: object
        :param location: The location
        :type location: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ResourceNameAvailability or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.netapp.models.ResourceNameAvailability or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.check_name_availability.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'location': self._serialize.url("location", location, 'str')
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
        body_content = self._serialize.body(body, 'object')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ResourceNameAvailability', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    check_name_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.NetApp/locations/{location}/checkNameAvailability'}

    def check_file_path_availability(
            self, body, location, custom_headers=None, raw=False, **operation_config):
        """Check file path availability.

        Check if a file path is available.

        :param body: File path availability request.
        :type body: object
        :param location: The location
        :type location: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ResourceNameAvailability or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.netapp.models.ResourceNameAvailability or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.check_file_path_availability.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'location': self._serialize.url("location", location, 'str')
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
        body_content = self._serialize.body(body, 'object')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ResourceNameAvailability', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    check_file_path_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.NetApp/locations/{location}/checkFilePathAvailability'}
