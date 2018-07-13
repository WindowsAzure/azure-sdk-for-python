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

from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from .version import VERSION


class KeyVaultManagementClientConfiguration(AzureConfiguration):
    """Configuration for KeyVaultManagementClient
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

        super(KeyVaultManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-keyvault/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class KeyVaultManagementClient(MultiApiClientMixin, SDKClient):
    """The Azure management API provides a RESTful set of web services that interact with Azure Key Vault.

    :ivar config: Configuration for client.
    :vartype config: KeyVaultManagementClientConfiguration

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str api_version: API version to use if no profile is provided, or if
     missing in profile.
    :param str base_url: Service URL
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    """

    DEFAULT_API_VERSION = '2018-02-14'
    _PROFILE_TAG = "azure.mgmt.keyvault.KeyVaultManagementClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(self, credentials, subscription_id, api_version=None, base_url=None, profile=KnownProfiles.default):
        super(KeyVaultManagementClient, self).__init__(
            credentials=credentials,
            subscription_id=subscription_id,
            api_version=api_version,
            base_url=base_url,
            profile=profile
        )

        self.config = KeyVaultManagementClient(credentials, subscription_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

############ Generated from here ############

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2016-10-01: :mod:`v2016_10_01.models<azure.mgmt.keyvault.v2016_10_01.models>`
           * 2018-02-14: :mod:`v2018_02_14.models<azure.mgmt.keyvault.v2018_02_14.models>`
        """
        if api_version == '2016-10-01':
            from .v2016_10_01 import models
            return models
        elif api_version == '2018-02-14':
            from .v2018_02_14 import models
            return models
        raise NotImplementedError("APIVersion {} is not available".format(api_version))
    
    @property
    def operations(self):
        """Instance depends on the API version:

           * 2016-10-01: :class:`Operations<azure.mgmt.keyvault.v2016_10_01.operations.Operations>`
           * 2018-02-14: :class:`Operations<azure.mgmt.keyvault.v2018_02_14.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2016-10-01':
            from .v2016_10_01.operations import Operations as OperationClass
        elif api_version == '2018-02-14':
            from .v2018_02_14.operations import Operations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def vaults(self):
        """Instance depends on the API version:

           * 2016-10-01: :class:`VaultsOperations<azure.mgmt.keyvault.v2016_10_01.operations.VaultsOperations>`
           * 2018-02-14: :class:`VaultsOperations<azure.mgmt.keyvault.v2018_02_14.operations.VaultsOperations>`
        """
        api_version = self._get_api_version('vaults')
        if api_version == '2016-10-01':
            from .v2016_10_01.operations import VaultsOperations as OperationClass
        elif api_version == '2018-02-14':
            from .v2018_02_14.operations import VaultsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))
