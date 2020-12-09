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

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Serializer, Deserializer

from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from ._configuration import ContainerServiceClientConfiguration

class _SDKClient(object):
    def __init__(self, *args, **kwargs):
        """This is a fake class to support current implemetation of MultiApiClientMixin."
        Will be removed in final version of multiapi azure-core based client
        """
        pass

class ContainerServiceClient(MultiApiClientMixin, _SDKClient):
    """The Container Service Client.

    This ready contains multiple API versions, to help you deal with all of the Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, it uses the latest API version available on public Azure.
    For production, you should stick to a particular api-version and/or profile.
    The profile sets a mapping between an operation group and its API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str api_version: API version to use if no profile is provided, or if
     missing in profile.
    :param str base_url: Service URL
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    DEFAULT_API_VERSION = '2020-11-01'
    _PROFILE_TAG = "azure.mgmt.containerservice.ContainerServiceClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
            'container_services': '2017-07-01',
            'open_shift_managed_clusters': '2019-04-30',
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(
        self,
        credential,  # type: "AsyncTokenCredential"
        subscription_id,  # type: str
        api_version=None,
        base_url=None,
        profile=KnownProfiles.default,
        **kwargs  # type: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = ContainerServiceClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)
        super(ContainerServiceClient, self).__init__(
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
           * 2019-09-30-preview: :mod:`v2019_09_30_preview.models<azure.mgmt.containerservice.v2019_09_30_preview.models>`
           * 2019-10-01: :mod:`v2019_10_01.models<azure.mgmt.containerservice.v2019_10_01.models>`
           * 2019-10-27-preview: :mod:`v2019_10_27_preview.models<azure.mgmt.containerservice.v2019_10_27_preview.models>`
           * 2019-11-01: :mod:`v2019_11_01.models<azure.mgmt.containerservice.v2019_11_01.models>`
           * 2020-01-01: :mod:`v2020_01_01.models<azure.mgmt.containerservice.v2020_01_01.models>`
           * 2020-02-01: :mod:`v2020_02_01.models<azure.mgmt.containerservice.v2020_02_01.models>`
           * 2020-03-01: :mod:`v2020_03_01.models<azure.mgmt.containerservice.v2020_03_01.models>`
           * 2020-04-01: :mod:`v2020_04_01.models<azure.mgmt.containerservice.v2020_04_01.models>`
           * 2020-06-01: :mod:`v2020_06_01.models<azure.mgmt.containerservice.v2020_06_01.models>`
           * 2020-07-01: :mod:`v2020_07_01.models<azure.mgmt.containerservice.v2020_07_01.models>`
           * 2020-09-01: :mod:`v2020_09_01.models<azure.mgmt.containerservice.v2020_09_01.models>`
           * 2020-11-01: :mod:`v2020_11_01.models<azure.mgmt.containerservice.v2020_11_01.models>`
        """
        if api_version == '2017-07-01':
            from ..v2017_07_01 import models
            return models
        elif api_version == '2018-03-31':
            from ..v2018_03_31 import models
            return models
        elif api_version == '2018-08-01-preview':
            from ..v2018_08_01_preview import models
            return models
        elif api_version == '2018-09-30-preview':
            from ..v2018_09_30_preview import models
            return models
        elif api_version == '2019-02-01':
            from ..v2019_02_01 import models
            return models
        elif api_version == '2019-04-01':
            from ..v2019_04_01 import models
            return models
        elif api_version == '2019-04-30':
            from ..v2019_04_30 import models
            return models
        elif api_version == '2019-06-01':
            from ..v2019_06_01 import models
            return models
        elif api_version == '2019-08-01':
            from ..v2019_08_01 import models
            return models
        elif api_version == '2019-09-30-preview':
            from ..v2019_09_30_preview import models
            return models
        elif api_version == '2019-10-01':
            from ..v2019_10_01 import models
            return models
        elif api_version == '2019-10-27-preview':
            from ..v2019_10_27_preview import models
            return models
        elif api_version == '2019-11-01':
            from ..v2019_11_01 import models
            return models
        elif api_version == '2020-01-01':
            from ..v2020_01_01 import models
            return models
        elif api_version == '2020-02-01':
            from ..v2020_02_01 import models
            return models
        elif api_version == '2020-03-01':
            from ..v2020_03_01 import models
            return models
        elif api_version == '2020-04-01':
            from ..v2020_04_01 import models
            return models
        elif api_version == '2020-06-01':
            from ..v2020_06_01 import models
            return models
        elif api_version == '2020-07-01':
            from ..v2020_07_01 import models
            return models
        elif api_version == '2020-09-01':
            from ..v2020_09_01 import models
            return models
        elif api_version == '2020-11-01':
            from ..v2020_11_01 import models
            return models
        raise ValueError("API version {} is not available".format(api_version))

    @property
    def agent_pools(self):
        """Instance depends on the API version:

           * 2019-02-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_02_01.aio.operations.AgentPoolsOperations>`
           * 2019-04-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_04_01.aio.operations.AgentPoolsOperations>`
           * 2019-06-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_06_01.aio.operations.AgentPoolsOperations>`
           * 2019-08-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_08_01.aio.operations.AgentPoolsOperations>`
           * 2019-10-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_10_01.aio.operations.AgentPoolsOperations>`
           * 2019-11-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2019_11_01.aio.operations.AgentPoolsOperations>`
           * 2020-01-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_01_01.aio.operations.AgentPoolsOperations>`
           * 2020-02-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_02_01.aio.operations.AgentPoolsOperations>`
           * 2020-03-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_03_01.aio.operations.AgentPoolsOperations>`
           * 2020-04-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_04_01.aio.operations.AgentPoolsOperations>`
           * 2020-06-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_06_01.aio.operations.AgentPoolsOperations>`
           * 2020-07-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_07_01.aio.operations.AgentPoolsOperations>`
           * 2020-09-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_09_01.aio.operations.AgentPoolsOperations>`
           * 2020-11-01: :class:`AgentPoolsOperations<azure.mgmt.containerservice.v2020_11_01.aio.operations.AgentPoolsOperations>`
        """
        api_version = self._get_api_version('agent_pools')
        if api_version == '2019-02-01':
            from ..v2019_02_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-04-01':
            from ..v2019_04_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-06-01':
            from ..v2019_06_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-08-01':
            from ..v2019_08_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-10-01':
            from ..v2019_10_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2019-11-01':
            from ..v2019_11_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-01-01':
            from ..v2020_01_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-02-01':
            from ..v2020_02_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-03-01':
            from ..v2020_03_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-04-01':
            from ..v2020_04_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-06-01':
            from ..v2020_06_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-07-01':
            from ..v2020_07_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-09-01':
            from ..v2020_09_01.aio.operations import AgentPoolsOperations as OperationClass
        elif api_version == '2020-11-01':
            from ..v2020_11_01.aio.operations import AgentPoolsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'agent_pools'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def container_services(self):
        """Instance depends on the API version:

           * 2017-07-01: :class:`ContainerServicesOperations<azure.mgmt.containerservice.v2017_07_01.aio.operations.ContainerServicesOperations>`
        """
        api_version = self._get_api_version('container_services')
        if api_version == '2017-07-01':
            from ..v2017_07_01.aio.operations import ContainerServicesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'container_services'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def managed_clusters(self):
        """Instance depends on the API version:

           * 2018-03-31: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2018_03_31.aio.operations.ManagedClustersOperations>`
           * 2018-08-01-preview: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2018_08_01_preview.aio.operations.ManagedClustersOperations>`
           * 2019-02-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_02_01.aio.operations.ManagedClustersOperations>`
           * 2019-04-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_04_01.aio.operations.ManagedClustersOperations>`
           * 2019-06-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_06_01.aio.operations.ManagedClustersOperations>`
           * 2019-08-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_08_01.aio.operations.ManagedClustersOperations>`
           * 2019-10-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_10_01.aio.operations.ManagedClustersOperations>`
           * 2019-11-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2019_11_01.aio.operations.ManagedClustersOperations>`
           * 2020-01-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_01_01.aio.operations.ManagedClustersOperations>`
           * 2020-02-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_02_01.aio.operations.ManagedClustersOperations>`
           * 2020-03-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_03_01.aio.operations.ManagedClustersOperations>`
           * 2020-04-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_04_01.aio.operations.ManagedClustersOperations>`
           * 2020-06-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_06_01.aio.operations.ManagedClustersOperations>`
           * 2020-07-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_07_01.aio.operations.ManagedClustersOperations>`
           * 2020-09-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_09_01.aio.operations.ManagedClustersOperations>`
           * 2020-11-01: :class:`ManagedClustersOperations<azure.mgmt.containerservice.v2020_11_01.aio.operations.ManagedClustersOperations>`
        """
        api_version = self._get_api_version('managed_clusters')
        if api_version == '2018-03-31':
            from ..v2018_03_31.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2018-08-01-preview':
            from ..v2018_08_01_preview.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-02-01':
            from ..v2019_02_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-04-01':
            from ..v2019_04_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-06-01':
            from ..v2019_06_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-08-01':
            from ..v2019_08_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-10-01':
            from ..v2019_10_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2019-11-01':
            from ..v2019_11_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-01-01':
            from ..v2020_01_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-02-01':
            from ..v2020_02_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-03-01':
            from ..v2020_03_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-04-01':
            from ..v2020_04_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-06-01':
            from ..v2020_06_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-07-01':
            from ..v2020_07_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-09-01':
            from ..v2020_09_01.aio.operations import ManagedClustersOperations as OperationClass
        elif api_version == '2020-11-01':
            from ..v2020_11_01.aio.operations import ManagedClustersOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'managed_clusters'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def open_shift_managed_clusters(self):
        """Instance depends on the API version:

           * 2018-09-30-preview: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2018_09_30_preview.aio.operations.OpenShiftManagedClustersOperations>`
           * 2019-04-30: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2019_04_30.aio.operations.OpenShiftManagedClustersOperations>`
           * 2019-09-30-preview: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2019_09_30_preview.aio.operations.OpenShiftManagedClustersOperations>`
           * 2019-10-27-preview: :class:`OpenShiftManagedClustersOperations<azure.mgmt.containerservice.v2019_10_27_preview.aio.operations.OpenShiftManagedClustersOperations>`
        """
        api_version = self._get_api_version('open_shift_managed_clusters')
        if api_version == '2018-09-30-preview':
            from ..v2018_09_30_preview.aio.operations import OpenShiftManagedClustersOperations as OperationClass
        elif api_version == '2019-04-30':
            from ..v2019_04_30.aio.operations import OpenShiftManagedClustersOperations as OperationClass
        elif api_version == '2019-09-30-preview':
            from ..v2019_09_30_preview.aio.operations import OpenShiftManagedClustersOperations as OperationClass
        elif api_version == '2019-10-27-preview':
            from ..v2019_10_27_preview.aio.operations import OpenShiftManagedClustersOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'open_shift_managed_clusters'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def operations(self):
        """Instance depends on the API version:

           * 2018-03-31: :class:`Operations<azure.mgmt.containerservice.v2018_03_31.aio.operations.Operations>`
           * 2018-08-01-preview: :class:`Operations<azure.mgmt.containerservice.v2018_08_01_preview.aio.operations.Operations>`
           * 2019-02-01: :class:`Operations<azure.mgmt.containerservice.v2019_02_01.aio.operations.Operations>`
           * 2019-04-01: :class:`Operations<azure.mgmt.containerservice.v2019_04_01.aio.operations.Operations>`
           * 2019-06-01: :class:`Operations<azure.mgmt.containerservice.v2019_06_01.aio.operations.Operations>`
           * 2019-08-01: :class:`Operations<azure.mgmt.containerservice.v2019_08_01.aio.operations.Operations>`
           * 2019-10-01: :class:`Operations<azure.mgmt.containerservice.v2019_10_01.aio.operations.Operations>`
           * 2019-11-01: :class:`Operations<azure.mgmt.containerservice.v2019_11_01.aio.operations.Operations>`
           * 2020-01-01: :class:`Operations<azure.mgmt.containerservice.v2020_01_01.aio.operations.Operations>`
           * 2020-02-01: :class:`Operations<azure.mgmt.containerservice.v2020_02_01.aio.operations.Operations>`
           * 2020-03-01: :class:`Operations<azure.mgmt.containerservice.v2020_03_01.aio.operations.Operations>`
           * 2020-04-01: :class:`Operations<azure.mgmt.containerservice.v2020_04_01.aio.operations.Operations>`
           * 2020-06-01: :class:`Operations<azure.mgmt.containerservice.v2020_06_01.aio.operations.Operations>`
           * 2020-07-01: :class:`Operations<azure.mgmt.containerservice.v2020_07_01.aio.operations.Operations>`
           * 2020-09-01: :class:`Operations<azure.mgmt.containerservice.v2020_09_01.aio.operations.Operations>`
           * 2020-11-01: :class:`Operations<azure.mgmt.containerservice.v2020_11_01.aio.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2018-03-31':
            from ..v2018_03_31.aio.operations import Operations as OperationClass
        elif api_version == '2018-08-01-preview':
            from ..v2018_08_01_preview.aio.operations import Operations as OperationClass
        elif api_version == '2019-02-01':
            from ..v2019_02_01.aio.operations import Operations as OperationClass
        elif api_version == '2019-04-01':
            from ..v2019_04_01.aio.operations import Operations as OperationClass
        elif api_version == '2019-06-01':
            from ..v2019_06_01.aio.operations import Operations as OperationClass
        elif api_version == '2019-08-01':
            from ..v2019_08_01.aio.operations import Operations as OperationClass
        elif api_version == '2019-10-01':
            from ..v2019_10_01.aio.operations import Operations as OperationClass
        elif api_version == '2019-11-01':
            from ..v2019_11_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-01-01':
            from ..v2020_01_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-02-01':
            from ..v2020_02_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-03-01':
            from ..v2020_03_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-04-01':
            from ..v2020_04_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-06-01':
            from ..v2020_06_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-07-01':
            from ..v2020_07_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-09-01':
            from ..v2020_09_01.aio.operations import Operations as OperationClass
        elif api_version == '2020-11-01':
            from ..v2020_11_01.aio.operations import Operations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'operations'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_endpoint_connections(self):
        """Instance depends on the API version:

           * 2020-06-01: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.containerservice.v2020_06_01.aio.operations.PrivateEndpointConnectionsOperations>`
           * 2020-07-01: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.containerservice.v2020_07_01.aio.operations.PrivateEndpointConnectionsOperations>`
           * 2020-09-01: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.containerservice.v2020_09_01.aio.operations.PrivateEndpointConnectionsOperations>`
           * 2020-11-01: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.containerservice.v2020_11_01.aio.operations.PrivateEndpointConnectionsOperations>`
        """
        api_version = self._get_api_version('private_endpoint_connections')
        if api_version == '2020-06-01':
            from ..v2020_06_01.aio.operations import PrivateEndpointConnectionsOperations as OperationClass
        elif api_version == '2020-07-01':
            from ..v2020_07_01.aio.operations import PrivateEndpointConnectionsOperations as OperationClass
        elif api_version == '2020-09-01':
            from ..v2020_09_01.aio.operations import PrivateEndpointConnectionsOperations as OperationClass
        elif api_version == '2020-11-01':
            from ..v2020_11_01.aio.operations import PrivateEndpointConnectionsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'private_endpoint_connections'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_link_resources(self):
        """Instance depends on the API version:

           * 2020-09-01: :class:`PrivateLinkResourcesOperations<azure.mgmt.containerservice.v2020_09_01.aio.operations.PrivateLinkResourcesOperations>`
           * 2020-11-01: :class:`PrivateLinkResourcesOperations<azure.mgmt.containerservice.v2020_11_01.aio.operations.PrivateLinkResourcesOperations>`
        """
        api_version = self._get_api_version('private_link_resources')
        if api_version == '2020-09-01':
            from ..v2020_09_01.aio.operations import PrivateLinkResourcesOperations as OperationClass
        elif api_version == '2020-11-01':
            from ..v2020_11_01.aio.operations import PrivateLinkResourcesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'private_link_resources'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def resolve_private_link_service_id(self):
        """Instance depends on the API version:

           * 2020-09-01: :class:`ResolvePrivateLinkServiceIdOperations<azure.mgmt.containerservice.v2020_09_01.aio.operations.ResolvePrivateLinkServiceIdOperations>`
           * 2020-11-01: :class:`ResolvePrivateLinkServiceIdOperations<azure.mgmt.containerservice.v2020_11_01.aio.operations.ResolvePrivateLinkServiceIdOperations>`
        """
        api_version = self._get_api_version('resolve_private_link_service_id')
        if api_version == '2020-09-01':
            from ..v2020_09_01.aio.operations import ResolvePrivateLinkServiceIdOperations as OperationClass
        elif api_version == '2020-11-01':
            from ..v2020_11_01.aio.operations import ResolvePrivateLinkServiceIdOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'resolve_private_link_service_id'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    async def close(self):
        await self._client.close()
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
