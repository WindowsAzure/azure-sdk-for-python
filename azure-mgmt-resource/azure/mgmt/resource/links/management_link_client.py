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
from ..version import VERSION


class ManagementLinkClientConfiguration(AzureConfiguration):
    """Configuration for ManagementLinkClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
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

        super(ManagementLinkClientConfiguration, self).__init__(base_url)

        self.add_user_agent('managementlinkclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class ManagementLinkClient(MultiApiClientMixin, SDKClient):
    """Azure resources can be linked together to form logical relationships. You can establish links between resources belonging to different resource groups. However, all the linked resources must belong to the same subscription. Each resource can be linked to 50 other resources. If any of the linked resources are deleted or moved, the link owner must clean up the remaining link.

    :ivar config: Configuration for client.
    :vartype config: ManagementLinkClientConfiguration

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param str api_version: API version to use if no profile is provided, or if
     missing in profile.
    :param str base_url: Service URL
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    """

    DEFAULT_API_VERSION = '2016-09-01'
    _PROFILE_TAG = "azure.mgmt.resource.links.ManagementLinkClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(self, credentials, subscription_id, api_version=None, base_url=None, profile=KnownProfiles.default):
        self.config = ManagementLinkClientConfiguration(credentials, subscription_id, base_url)
        super(ManagementLinkClient, self).__init__(
            credentials,
            self.config,
            api_version=api_version,
            profile=profile
        )

############ Generated from here ############

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2016-09-01: :mod:`v2016_09_01.models<azure.mgmt.resource.links.v2016_09_01.models>`
        """
        if api_version == '2016-09-01':
            from .v2016_09_01 import models
            return models
        raise NotImplementedError("APIVersion {} is not available".format(api_version))

    @property
    def operations(self):
        """Instance depends on the API version:

           * 2016-09-01: :class:`Operations<azure.mgmt.resource.links.v2016_09_01.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2016-09-01':
            from .v2016_09_01.operations import Operations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def resource_links(self):
        """Instance depends on the API version:

           * 2016-09-01: :class:`ResourceLinksOperations<azure.mgmt.resource.links.v2016_09_01.operations.ResourceLinksOperations>`
        """
        api_version = self._get_api_version('resource_links')
        if api_version == '2016-09-01':
            from .v2016_09_01.operations import ResourceLinksOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))
