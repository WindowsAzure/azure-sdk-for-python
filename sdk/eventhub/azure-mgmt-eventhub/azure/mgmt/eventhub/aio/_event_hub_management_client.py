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

from typing import Any, Optional, TYPE_CHECKING

from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core import AsyncARMPipelineClient
from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from msrest import Deserializer, Serializer

from ._configuration import EventHubManagementClientConfiguration

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

class _SDKClient(object):
    def __init__(self, *args, **kwargs):
        """This is a fake class to support current implemetation of MultiApiClientMixin."
        Will be removed in final version of multiapi azure-core based client
        """
        pass

class EventHubManagementClient(MultiApiClientMixin, _SDKClient):
    """Azure Event Hubs client.

    This ready contains multiple API versions, to help you deal with all of the Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, it uses the latest API version available on public Azure.
    For production, you should stick to a particular api-version and/or profile.
    The profile sets a mapping between an operation group and its API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription credentials that uniquely identify a Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param api_version: API version to use if no profile is provided, or if missing in profile.
    :type api_version: str
    :param base_url: Service URL
    :type base_url: str
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    DEFAULT_API_VERSION = '2017-04-01'
    _PROFILE_TAG = "azure.mgmt.eventhub.EventHubManagementClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        api_version: Optional[str] = None,
        base_url: Optional[str] = None,
        profile: KnownProfiles = KnownProfiles.default,
        **kwargs  # type: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = EventHubManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)
        super(EventHubManagementClient, self).__init__(
            api_version=api_version,
            profile=profile
        )

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2015-08-01: :mod:`v2015_08_01.models<azure.mgmt.eventhub.v2015_08_01.models>`
           * 2017-04-01: :mod:`v2017_04_01.models<azure.mgmt.eventhub.v2017_04_01.models>`
           * 2018-01-01-preview: :mod:`v2018_01_01_preview.models<azure.mgmt.eventhub.v2018_01_01_preview.models>`
           * 2021-01-01-preview: :mod:`v2021_01_01_preview.models<azure.mgmt.eventhub.v2021_01_01_preview.models>`
        """
        if api_version == '2015-08-01':
            from ..v2015_08_01 import models
            return models
        elif api_version == '2017-04-01':
            from ..v2017_04_01 import models
            return models
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview import models
            return models
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview import models
            return models
        raise ValueError("API version {} is not available".format(api_version))

    @property
    def clusters(self):
        """Instance depends on the API version:

           * 2018-01-01-preview: :class:`ClustersOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.ClustersOperations>`
        """
        api_version = self._get_api_version('clusters')
        if api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import ClustersOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'clusters'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def configuration(self):
        """Instance depends on the API version:

           * 2018-01-01-preview: :class:`ConfigurationOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.ConfigurationOperations>`
        """
        api_version = self._get_api_version('configuration')
        if api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import ConfigurationOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'configuration'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def consumer_groups(self):
        """Instance depends on the API version:

           * 2015-08-01: :class:`ConsumerGroupsOperations<azure.mgmt.eventhub.v2015_08_01.aio.operations.ConsumerGroupsOperations>`
           * 2017-04-01: :class:`ConsumerGroupsOperations<azure.mgmt.eventhub.v2017_04_01.aio.operations.ConsumerGroupsOperations>`
           * 2018-01-01-preview: :class:`ConsumerGroupsOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.ConsumerGroupsOperations>`
           * 2021-01-01-preview: :class:`ConsumerGroupsOperations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.ConsumerGroupsOperations>`
        """
        api_version = self._get_api_version('consumer_groups')
        if api_version == '2015-08-01':
            from ..v2015_08_01.aio.operations import ConsumerGroupsOperations as OperationClass
        elif api_version == '2017-04-01':
            from ..v2017_04_01.aio.operations import ConsumerGroupsOperations as OperationClass
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import ConsumerGroupsOperations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import ConsumerGroupsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'consumer_groups'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def disaster_recovery_configs(self):
        """Instance depends on the API version:

           * 2017-04-01: :class:`DisasterRecoveryConfigsOperations<azure.mgmt.eventhub.v2017_04_01.aio.operations.DisasterRecoveryConfigsOperations>`
           * 2018-01-01-preview: :class:`DisasterRecoveryConfigsOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.DisasterRecoveryConfigsOperations>`
           * 2021-01-01-preview: :class:`DisasterRecoveryConfigsOperations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.DisasterRecoveryConfigsOperations>`
        """
        api_version = self._get_api_version('disaster_recovery_configs')
        if api_version == '2017-04-01':
            from ..v2017_04_01.aio.operations import DisasterRecoveryConfigsOperations as OperationClass
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import DisasterRecoveryConfigsOperations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import DisasterRecoveryConfigsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'disaster_recovery_configs'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def event_hubs(self):
        """Instance depends on the API version:

           * 2015-08-01: :class:`EventHubsOperations<azure.mgmt.eventhub.v2015_08_01.aio.operations.EventHubsOperations>`
           * 2017-04-01: :class:`EventHubsOperations<azure.mgmt.eventhub.v2017_04_01.aio.operations.EventHubsOperations>`
           * 2018-01-01-preview: :class:`EventHubsOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.EventHubsOperations>`
           * 2021-01-01-preview: :class:`EventHubsOperations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.EventHubsOperations>`
        """
        api_version = self._get_api_version('event_hubs')
        if api_version == '2015-08-01':
            from ..v2015_08_01.aio.operations import EventHubsOperations as OperationClass
        elif api_version == '2017-04-01':
            from ..v2017_04_01.aio.operations import EventHubsOperations as OperationClass
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import EventHubsOperations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import EventHubsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'event_hubs'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def namespaces(self):
        """Instance depends on the API version:

           * 2015-08-01: :class:`NamespacesOperations<azure.mgmt.eventhub.v2015_08_01.aio.operations.NamespacesOperations>`
           * 2017-04-01: :class:`NamespacesOperations<azure.mgmt.eventhub.v2017_04_01.aio.operations.NamespacesOperations>`
           * 2018-01-01-preview: :class:`NamespacesOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.NamespacesOperations>`
           * 2021-01-01-preview: :class:`NamespacesOperations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.NamespacesOperations>`
        """
        api_version = self._get_api_version('namespaces')
        if api_version == '2015-08-01':
            from ..v2015_08_01.aio.operations import NamespacesOperations as OperationClass
        elif api_version == '2017-04-01':
            from ..v2017_04_01.aio.operations import NamespacesOperations as OperationClass
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import NamespacesOperations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import NamespacesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'namespaces'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def operations(self):
        """Instance depends on the API version:

           * 2015-08-01: :class:`Operations<azure.mgmt.eventhub.v2015_08_01.aio.operations.Operations>`
           * 2017-04-01: :class:`Operations<azure.mgmt.eventhub.v2017_04_01.aio.operations.Operations>`
           * 2018-01-01-preview: :class:`Operations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.Operations>`
           * 2021-01-01-preview: :class:`Operations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2015-08-01':
            from ..v2015_08_01.aio.operations import Operations as OperationClass
        elif api_version == '2017-04-01':
            from ..v2017_04_01.aio.operations import Operations as OperationClass
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import Operations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import Operations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'operations'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_endpoint_connections(self):
        """Instance depends on the API version:

           * 2018-01-01-preview: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.PrivateEndpointConnectionsOperations>`
           * 2021-01-01-preview: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.PrivateEndpointConnectionsOperations>`
        """
        api_version = self._get_api_version('private_endpoint_connections')
        if api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import PrivateEndpointConnectionsOperations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import PrivateEndpointConnectionsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'private_endpoint_connections'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_link_resources(self):
        """Instance depends on the API version:

           * 2018-01-01-preview: :class:`PrivateLinkResourcesOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.PrivateLinkResourcesOperations>`
           * 2021-01-01-preview: :class:`PrivateLinkResourcesOperations<azure.mgmt.eventhub.v2021_01_01_preview.aio.operations.PrivateLinkResourcesOperations>`
        """
        api_version = self._get_api_version('private_link_resources')
        if api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import PrivateLinkResourcesOperations as OperationClass
        elif api_version == '2021-01-01-preview':
            from ..v2021_01_01_preview.aio.operations import PrivateLinkResourcesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'private_link_resources'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def regions(self):
        """Instance depends on the API version:

           * 2017-04-01: :class:`RegionsOperations<azure.mgmt.eventhub.v2017_04_01.aio.operations.RegionsOperations>`
           * 2018-01-01-preview: :class:`RegionsOperations<azure.mgmt.eventhub.v2018_01_01_preview.aio.operations.RegionsOperations>`
        """
        api_version = self._get_api_version('regions')
        if api_version == '2017-04-01':
            from ..v2017_04_01.aio.operations import RegionsOperations as OperationClass
        elif api_version == '2018-01-01-preview':
            from ..v2018_01_01_preview.aio.operations import RegionsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'regions'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    async def close(self):
        await self._client.close()
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
