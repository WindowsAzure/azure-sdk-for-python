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

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from msrest import Deserializer, Serializer

from ._configuration import SearchClientConfiguration
from ._operations_mixin import SearchClientOperationsMixin

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.pipeline.transport import HttpRequest, HttpResponse

class _SDKClient(object):
    def __init__(self, *args, **kwargs):
        """This is a fake class to support current implemetation of MultiApiClientMixin."
        Will be removed in final version of multiapi azure-core based client
        """
        pass

class SearchClient(SearchClientOperationsMixin, MultiApiClientMixin, _SDKClient):
    """Client that can be used to manage and query indexes and documents, as well as manage other resources, on a search service.

    This ready contains multiple API versions, to help you deal with all of the Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, it uses the latest API version available on public Azure.
    For production, you should stick to a particular api-version and/or profile.
    The profile sets a mapping between an operation group and its API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :param endpoint: The endpoint URL of the search service.
    :type endpoint: str
    :param api_version: API version to use if no profile is provided, or if missing in profile.
    :type api_version: str
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    """

    DEFAULT_API_VERSION = '2020-06-30-Preview'
    _PROFILE_TAG = "azure.search.documents.SearchClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(
        self,
        endpoint,  # type: str
        api_version=None, # type: Optional[str]
        profile=KnownProfiles.default, # type: KnownProfiles
        **kwargs  # type: Any
    ):
        if api_version == '2020-06-30' or api_version == '2020-06-30-Preview':
            base_url = '{endpoint}'
        else:
            raise ValueError("API version {} is not available".format(api_version))
        self._config = SearchClientConfiguration(endpoint, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)
        super(SearchClient, self).__init__(
            api_version=api_version,
            profile=profile
        )

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2020-06-30: :mod:`v2020_06.models<azure.search.documents.v2020_06.models>`
           * 2020-06-30-Preview: :mod:`v2020_06_preview.models<azure.search.documents.v2020_06_preview.models>`
        """
        if api_version == '2020-06-30':
            from .v2020_06 import models
            return models
        elif api_version == '2020-06-30-Preview':
            from .v2020_06_preview import models
            return models
        raise ValueError("API version {} is not available".format(api_version))

    @property
    def data_sources(self):
        """Instance depends on the API version:

           * 2020-06-30: :class:`DataSourcesOperations<azure.search.documents.v2020_06.operations.DataSourcesOperations>`
           * 2020-06-30-Preview: :class:`DataSourcesOperations<azure.search.documents.v2020_06_preview.operations.DataSourcesOperations>`
        """
        api_version = self._get_api_version('data_sources')
        if api_version == '2020-06-30':
            from .v2020_06.operations import DataSourcesOperations as OperationClass
        elif api_version == '2020-06-30-Preview':
            from .v2020_06_preview.operations import DataSourcesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'data_sources'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def indexers(self):
        """Instance depends on the API version:

           * 2020-06-30: :class:`IndexersOperations<azure.search.documents.v2020_06.operations.IndexersOperations>`
           * 2020-06-30-Preview: :class:`IndexersOperations<azure.search.documents.v2020_06_preview.operations.IndexersOperations>`
        """
        api_version = self._get_api_version('indexers')
        if api_version == '2020-06-30':
            from .v2020_06.operations import IndexersOperations as OperationClass
        elif api_version == '2020-06-30-Preview':
            from .v2020_06_preview.operations import IndexersOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'indexers'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def indexes(self):
        """Instance depends on the API version:

           * 2020-06-30: :class:`IndexesOperations<azure.search.documents.v2020_06.operations.IndexesOperations>`
           * 2020-06-30-Preview: :class:`IndexesOperations<azure.search.documents.v2020_06_preview.operations.IndexesOperations>`
        """
        api_version = self._get_api_version('indexes')
        if api_version == '2020-06-30':
            from .v2020_06.operations import IndexesOperations as OperationClass
        elif api_version == '2020-06-30-Preview':
            from .v2020_06_preview.operations import IndexesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'indexes'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def skillsets(self):
        """Instance depends on the API version:

           * 2020-06-30: :class:`SkillsetsOperations<azure.search.documents.v2020_06.operations.SkillsetsOperations>`
           * 2020-06-30-Preview: :class:`SkillsetsOperations<azure.search.documents.v2020_06_preview.operations.SkillsetsOperations>`
        """
        api_version = self._get_api_version('skillsets')
        if api_version == '2020-06-30':
            from .v2020_06.operations import SkillsetsOperations as OperationClass
        elif api_version == '2020-06-30-Preview':
            from .v2020_06_preview.operations import SkillsetsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'skillsets'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def synonym_maps(self):
        """Instance depends on the API version:

           * 2020-06-30: :class:`SynonymMapsOperations<azure.search.documents.v2020_06.operations.SynonymMapsOperations>`
           * 2020-06-30-Preview: :class:`SynonymMapsOperations<azure.search.documents.v2020_06_preview.operations.SynonymMapsOperations>`
        """
        api_version = self._get_api_version('synonym_maps')
        if api_version == '2020-06-30':
            from .v2020_06.operations import SynonymMapsOperations as OperationClass
        elif api_version == '2020-06-30-Preview':
            from .v2020_06_preview.operations import SynonymMapsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'synonym_maps'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    def close(self):
        self._client.close()
    def __enter__(self):
        self._client.__enter__()
        return self
    def __exit__(self, *exc_details):
        self._client.__exit__(*exc_details)
