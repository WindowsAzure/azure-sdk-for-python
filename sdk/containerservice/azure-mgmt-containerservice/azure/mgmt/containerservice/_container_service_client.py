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
from ._configuration import ContainerServiceClientConfiguration



class ContainerServiceClient(MultiApiClientMixin, SDKClient):
    """The Container Service Client.

    This ready contains multiple API versions, to help you deal with all Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, uses latest API version available on public Azure.
    For production, you should stick a particular api-version and/or profile.
    The profile sets a mapping between the operation group and an API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :ivar config: Configuration for client.
    :vartype config: ContainerServiceClientConfiguration

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

    DEFAULT_API_VERSION = '2019-08-01'
    _PROFILE_TAG = "azure.mgmt.containerservice.ContainerServiceClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
            'container_services': '2017-07-01',
            'open_shift_managed_clusters': '2019-04-30',
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(self, credentials, subscription_id, api_version=None, base_url=None, profile=KnownProfiles.default):
        self.config = ContainerServiceClientConfiguration(credentials, subscription_id, base_url)
        super(ContainerServiceClient, self).__init__(
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

           * 2017-07-01: :mod:`v2017_07_01.models<azure.mgmt.containerservice.v2017_07_01.models>`
           * 2018-03-31: :mod:`v2018_03_31.models<azure.mgmt.containerservice.v2018_03_31.models>`
           * 2018-08-01-preview: :mod:`v2018_08_01_preview.models<azure.mgmt.containerservice.v2018_08_01_preview.models>`
           * 2018-09-30-preview: :mod:`v2018_09_30_preview.models<azure.mgmt.containerservice.v2018_09_30_preview.models>`
           * 2019-02-01: :mod:`v2019_02_01.models<azure.mgmt.containerservice.v2019_02_01.models>`
           * 2019-04-01: :mod:`v2019_04_01.models<azure.mgmt.containerservice.v2019_04_01.models>`
           * 2019-04-30: :mod:`v2019_04_30.models<azure.mgmt.containerservice.v2019_04_30.models>`
           * 2019-06-01: :mod:`v2019_06_01.models<azure.mgmt.containerservice.v2019_06_01.models>`
           * 2019-08-01: :mod:`v2019_08_01.models<azure.mgmt.containerservice.v2019_08_01.models>`
           * 2019-04-30: :mod:`v2019_09_30_preview.models<azure.mgmt.containerservice.v2019_09_30_preview.models>`
        """
        if api_version == '2017-07-01':
            from .v2017_07_01 import models
            return models
        elif api_version == '2018-03-31':
            from .v2018_03_31 import models
            return models
        elif api_version == '2018-08-01-preview':
            from .v2018_08_01_preview import models
            return models
        elif api_version == '2018-09-30-preview':
            from .v2018_09_30_preview import models
            return models
        elif api_version == '2019-02-01':
            from .v2019_02_01 import models
            return models
        elif api_version == '2019-04-01':
            from .v2019_04_01 import models
            return models
        elif api_version == '2019-04-30':
            from .v2019_04_30 import models
            return models
        elif api_version == '2019-06-01':
            from .v2019_06_01 import models
            return models
        elif api_version == '2019-08-01':
            from .v2019_08_01 import models
            return models
        elif api_version == '2019-04-30':
            from .v2019_09_30_preview import models
            return models
        raise NotImplementedError("APIVersion {} is not available".format(api_version))

    @property
    def agent_pools(self):
        """Instance depends on the API version:

           * 2019-02-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_02_01.operations.AgentPoolsOperations>`
           * 2019-04-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_04_01.operations.AgentPoolsOperations>`
           * 2019-06-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_06_01.operations.AgentPoolsOperations>`
           * 2019-08-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_08_01.operations.AgentPoolsOperations>`
        """
        api_version = self._get_api_version('agent_pools')
        if api_version == '2019-02-01':
            from .v2019_02_01.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-04-01':
            from .v2019_04_01.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-06-01':
            from .v2019_06_01.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import AgentPoolsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def container_services(self):
        """Instance depends on the API version:

           * 2017-07-01: :class:`ContainerServicesOperations<azure.mgmt.containerservice.v2017_07_01.operations.ContainerServicesOperations>`
        """
        api_version = self._get_api_version('container_services')
        if api_version == '2017-07-01':
            from .v2017_07_01.operations import ContainerServicesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def managed_clusters(self):
        """Instance depends on the API version:

           * 2018-03-31: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2018_03_31.operations.ManagedClustersOperations>`
           * 2018-08-01-preview: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2018_08_01_preview.operations.ManagedClustersOperations>`
           * 2019-02-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_02_01.operations.ManagedClustersOperations>`
           * 2019-04-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_04_01.operations.ManagedClustersOperations>`
           * 2019-06-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_06_01.operations.ManagedClustersOperations>`
           * 2019-08-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_08_01.operations.ManagedClustersOperations>`
        """
        api_version = self._get_api_version('managed_clusters')
        if api_version == '2018-03-31':
            from .v2018_03_31.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2018-08-01-preview':
            from .v2018_08_01_preview.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-02-01':
            from .v2019_02_01.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-04-01':
            from .v2019_04_01.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-06-01':
            from .v2019_06_01.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import ManagedClustersOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def open_shift_managed_clusters(self):
        """Instance depends on the API version:

           * 2018-09-30-preview: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2018_09_30_preview.operations.OpenShiftManagedClustersOperations>`
           * 2019-04-30: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2019_04_30.operations.OpenShiftManagedClustersOperations>`
           * 2019-04-30: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2019_09_30_preview.operations.OpenShiftManagedClustersOperations>`
        """
        api_version = self._get_api_version('open_shift_managed_clusters')
        if api_version == '2018-09-30-preview':
            from .v2018_09_30_preview.operations import OpenShiftManagedClustersOperations as OperationClass
        elif api_version == '2019-04-30':
            from .v2019_04_30.operations import OpenShiftManagedClustersOperations as OperationClass
        elif api_version == '2019-04-30':
            from .v2019_09_30_preview.operations import OpenShiftManagedClustersOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def operations(self):
        """Instance depends on the API version:

           * 2018-03-31: :class:`Operations<azure.mgmt.containerservice.v2018_03_31.operations.Operations>`
           * 2018-08-01-preview: :class:`Operations<azure.mgmt.containerservice.v2018_08_01_preview.operations.Operations>`
           * 2019-02-01: :class:`Operations<azure.mgmt.containerservice.v2019_02_01.operations.Operations>`
           * 2019-04-01: :class:`Operations<azure.mgmt.containerservice.v2019_04_01.operations.Operations>`
           * 2019-06-01: :class:`Operations<azure.mgmt.containerservice.v2019_06_01.operations.Operations>`
           * 2019-08-01: :class:`Operations<azure.mgmt.containerservice.v2019_08_01.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2018-03-31':
            from .v2018_03_31.operations import Operations as OperationClass
        elif api_version == '2018-08-01-preview':
            from .v2018_08_01_preview.operations import Operations as OperationClass
        elif api_version == '2019-02-01':
            from .v2019_02_01.operations import Operations as OperationClass
        elif api_version == '2019-04-01':
            from .v2019_04_01.operations import Operations as OperationClass
        elif api_version == '2019-06-01':
            from .v2019_06_01.operations import Operations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import Operations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self.config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))
