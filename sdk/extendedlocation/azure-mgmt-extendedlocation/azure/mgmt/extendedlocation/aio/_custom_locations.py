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
from ._configuration import CustomLocationsConfiguration

class _SDKClient(object):
    def __init__(self, *args, **kwargs):
        """This is a fake class to support current implemetation of MultiApiClientMixin."
        Will be removed in final version of multiapi azure-core based client
        """
        pass

class CustomLocations(MultiApiClientMixin, _SDKClient):
    """The customLocations Rest API spec.

    This ready contains multiple API versions, to help you deal with all of the Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, it uses the latest API version available on public Azure.
    For production, you should stick to a particular api-version and/or profile.
    The profile sets a mapping between an operation group and its API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param str api_version: API version to use if no profile is provided, or if
     missing in profile.
    :param str base_url: Service URL
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    DEFAULT_API_VERSION = '2021-03-15-preview'
    _PROFILE_TAG = "azure.mgmt.extendedlocation.CustomLocations"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
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
        self._config = CustomLocationsConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)
        super(CustomLocations, self).__init__(
            api_version=api_version,
            profile=profile
        )

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2020-07-15-privatepreview: :mod:`v2020_07_15_privatepreview.models<azure.mgmt.extendedlocation.v2020_07_15_privatepreview.models>`
           * 2021-03-15-preview: :mod:`v2021_03_15_preview.models<azure.mgmt.extendedlocation.v2021_03_15_preview.models>`
        """
        if api_version == '2020-07-15-privatepreview':
            from ..v2020_07_15_privatepreview import models
            return models
        elif api_version == '2021-03-15-preview':
            from ..v2021_03_15_preview import models
            return models
        raise ValueError("API version {} is not available".format(api_version))

    @property
    def custom_locations(self):
        """Instance depends on the API version:

           * 2020-07-15-privatepreview: :class:`CustomLocationsOperations<azure.mgmt.extendedlocation.v2020_07_15_privatepreview.aio.operations.CustomLocationsOperations>`
           * 2021-03-15-preview: :class:`CustomLocationsOperations<azure.mgmt.extendedlocation.v2021_03_15_preview.aio.operations.CustomLocationsOperations>`
        """
        api_version = self._get_api_version('custom_locations')
        if api_version == '2020-07-15-privatepreview':
            from ..v2020_07_15_privatepreview.aio.operations import CustomLocationsOperations as OperationClass
        elif api_version == '2021-03-15-preview':
            from ..v2021_03_15_preview.aio.operations import CustomLocationsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'custom_locations'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    async def close(self):
        await self._client.close()
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    async def __aexit__(self, *exc_details):
        await self._client.__aexit__(*exc_details)
