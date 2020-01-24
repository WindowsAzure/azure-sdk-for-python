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

from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from ._configuration import IotHubClientConfiguration



class IotHubClient(MultiApiClientMixin, SDKClient):
    """Use this API to manage the IoT hubs in your Azure subscription.

    This ready contains multiple API versions, to help you deal with all Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, uses latest API version available on public Azure.
    For production, you should stick a particular api-version and/or profile.
    The profile sets a mapping between the operation group and an API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :ivar config: Configuration for client.
    :vartype config: IotHubClientConfiguration

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

    DEFAULT_API_VERSION = '2019-11-04'
    _PROFILE_TAG = "azure.mgmt.iothub.IotHubClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(self, credentials, subscription_id, api_version=None, base_url=None, profile=KnownProfiles.default):
        self.config = IotHubClientConfiguration(credentials, subscription_id, base_url)
        super(IotHubClient, self).__init__(
            credentials,
            self.config,
            api_version=api_version,
            profile=profile
        )

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2016-02-03: :mod:`v2016_02_03.models<azure.mgmt.iothub.v2016_02_03.models>`
           * 2017-01-19: :mod:`v2017_01_19.models<azure.mgmt.iothub.v2017_01_19.models>`
           * 2017-07-01: :mod:`v2017_07_01.models<azure.mgmt.iothub.v2017_07_01.models>`
           * 2018-01-22: :mod:`v2018_01_22.models<azure.mgmt.iothub.v2018_01_22.models>`
           * 2018-04-01: :mod:`v2018_04_01.models<azure.mgmt.iothub.v2018_04_01.models>`
           * 2019-03-22: :mod:`v2019_03_22.models<azure.mgmt.iothub.v2019_03_22.models>`
           * 2019-11-04: :mod:`v2019_11_04.models<azure.mgmt.iothub.v2019_11_04.models>`
        """
        if api_version == '2016-02-03':
            from .v2016_02_03 import models
            return models
        elif api_version == '2017-01-19':
            from .v2017_01_19 import models
            return models
        elif api_version == '2017-07-01':
            from .v2017_07_01 import models
            return models
        elif api_version == '2018-01-22':
            from .v2018_01_22 import models
            return models
        elif api_version == '2018-04-01':
            from .v2018_04_01 import models
            return models
        elif api_version == '2019-03-22':
            from .v2019_03_22 import models
            return models
        elif api_version == '2019-11-04':
            from .v2019_11_04 import models
            return models
        raise NotImplementedError("APIVersion {} is not available".format(api_version))

    @property
    def certificates(self):
        """Instance depends on the API version:

           * 2017-07-01: :class:`CertificatesOperations<azure.mgmt.iothub.v2017_07_01.operations.CertificatesOperations>`
           * 2018-01-22: :class:`CertificatesOperations<azure.mgmt.iothub.v2018_01_22.operations.CertificatesOperations>`
           * 2018-04-01: :class:`CertificatesOperations<azure.mgmt.iothub.v2018_04_01.operations.CertificatesOperations>`
           * 2019-03-22: :class:`CertificatesOperations<azure.mgmt.iothub.v2019_03_22.operations.CertificatesOperations>`
           * 2019-11-04: :class:`CertificatesOperations<azure.mgmt.iothub.v2019_11_04.operations.CertificatesOperations>`
        """
        api_version = self._get_api_version('certificates')
        if api_version == '2017-07-01':
            from .v2017_07_01.operations import CertificatesOperations as OperationClass
        elif api_version == '2018-01-22':
            from .v2018_01_22.operations import CertificatesOperations as OperationClass
        elif api_version == '2018-04-01':
            from .v2018_04_01.operations import CertificatesOperations as OperationClass
        elif api_version == '2019-03-22':
            from .v2019_03_22.operations import CertificatesOperations as OperationClass
        elif api_version == '2019-11-04':
            from .v2019_11_04.operations import CertificatesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def iot_hub(self):
        """Instance depends on the API version:

           * 2019-03-22: :class:`IotHubOperations<azure.mgmt.iothub.v2019_03_22.operations.IotHubOperations>`
           * 2019-11-04: :class:`IotHubOperations<azure.mgmt.iothub.v2019_11_04.operations.IotHubOperations>`
        """
        api_version = self._get_api_version('iot_hub')
        if api_version == '2019-03-22':
            from .v2019_03_22.operations import IotHubOperations as OperationClass
        elif api_version == '2019-11-04':
            from .v2019_11_04.operations import IotHubOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def iot_hub_resource(self):
        """Instance depends on the API version:

           * 2016-02-03: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2016_02_03.operations.IotHubResourceOperations>`
           * 2017-01-19: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2017_01_19.operations.IotHubResourceOperations>`
           * 2017-07-01: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2017_07_01.operations.IotHubResourceOperations>`
           * 2018-01-22: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2018_01_22.operations.IotHubResourceOperations>`
           * 2018-04-01: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2018_04_01.operations.IotHubResourceOperations>`
           * 2019-03-22: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2019_03_22.operations.IotHubResourceOperations>`
           * 2019-11-04: :class:`IotHubResourceOperations<azure.mgmt.iothub.v2019_11_04.operations.IotHubResourceOperations>`
        """
        api_version = self._get_api_version('iot_hub_resource')
        if api_version == '2016-02-03':
            from .v2016_02_03.operations import IotHubResourceOperations as OperationClass
        elif api_version == '2017-01-19':
            from .v2017_01_19.operations import IotHubResourceOperations as OperationClass
        elif api_version == '2017-07-01':
            from .v2017_07_01.operations import IotHubResourceOperations as OperationClass
        elif api_version == '2018-01-22':
            from .v2018_01_22.operations import IotHubResourceOperations as OperationClass
        elif api_version == '2018-04-01':
            from .v2018_04_01.operations import IotHubResourceOperations as OperationClass
        elif api_version == '2019-03-22':
            from .v2019_03_22.operations import IotHubResourceOperations as OperationClass
        elif api_version == '2019-11-04':
            from .v2019_11_04.operations import IotHubResourceOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def operations(self):
        """Instance depends on the API version:

           * 2017-07-01: :class:`Operations<azure.mgmt.iothub.v2017_07_01.operations.Operations>`
           * 2018-01-22: :class:`Operations<azure.mgmt.iothub.v2018_01_22.operations.Operations>`
           * 2018-04-01: :class:`Operations<azure.mgmt.iothub.v2018_04_01.operations.Operations>`
           * 2019-03-22: :class:`Operations<azure.mgmt.iothub.v2019_03_22.operations.Operations>`
           * 2019-11-04: :class:`Operations<azure.mgmt.iothub.v2019_11_04.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2017-07-01':
            from .v2017_07_01.operations import Operations as OperationClass
        elif api_version == '2018-01-22':
            from .v2018_01_22.operations import Operations as OperationClass
        elif api_version == '2018-04-01':
            from .v2018_04_01.operations import Operations as OperationClass
        elif api_version == '2019-03-22':
            from .v2019_03_22.operations import Operations as OperationClass
        elif api_version == '2019-11-04':
            from .v2019_11_04.operations import Operations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def resource_provider_common(self):
        """Instance depends on the API version:

           * 2018-04-01: :class:`ResourceProviderCommonOperations<azure.mgmt.iothub.v2018_04_01.operations.ResourceProviderCommonOperations>`
           * 2019-03-22: :class:`ResourceProviderCommonOperations<azure.mgmt.iothub.v2019_03_22.operations.ResourceProviderCommonOperations>`
           * 2019-11-04: :class:`ResourceProviderCommonOperations<azure.mgmt.iothub.v2019_11_04.operations.ResourceProviderCommonOperations>`
        """
        api_version = self._get_api_version('resource_provider_common')
        if api_version == '2018-04-01':
            from .v2018_04_01.operations import ResourceProviderCommonOperations as OperationClass
        elif api_version == '2019-03-22':
            from .v2019_03_22.operations import ResourceProviderCommonOperations as OperationClass
        elif api_version == '2019-11-04':
            from .v2019_11_04.operations import ResourceProviderCommonOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))
