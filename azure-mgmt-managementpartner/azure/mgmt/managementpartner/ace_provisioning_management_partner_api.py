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
from .operations.partner_operations import PartnerOperations
from .operations.operation_operations import OperationOperations
from . import models


class ACEProvisioningManagementPartnerAPIConfiguration(AzureConfiguration):
    """Configuration for ACEProvisioningManagementPartnerAPI
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
            base_url = 'https://management.azure.com'

        super(ACEProvisioningManagementPartnerAPIConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-managementpartner/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials


class ACEProvisioningManagementPartnerAPI(SDKClient):
    """This API describe ACE Provisioning ManagementPartner

    :ivar config: Configuration for client.
    :vartype config: ACEProvisioningManagementPartnerAPIConfiguration

    :ivar partner: Partner operations
    :vartype partner: azure.mgmt.managementpartner.operations.PartnerOperations
    :ivar operation: Operation operations
    :vartype operation: azure.mgmt.managementpartner.operations.OperationOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        self.config = ACEProvisioningManagementPartnerAPIConfiguration(credentials, base_url)
        super(ACEProvisioningManagementPartnerAPI, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-02-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.partner = PartnerOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operation = OperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
