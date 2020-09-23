# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import TemplateSpecsClientConfiguration
from .operations import TemplateSpecsOperations
from .operations import TemplateSpecVersionsOperations
from .. import models


class TemplateSpecsClient(object):
    """The APIs listed in this specification can be used to manage Template Spec resources through the Azure Resource Manager.

    :ivar template_specs: TemplateSpecsOperations operations
    :vartype template_specs: azure.mgmt.resource.templatespecs.v2019_06_01_preview.aio.operations.TemplateSpecsOperations
    :ivar template_spec_versions: TemplateSpecVersionsOperations operations
    :vartype template_spec_versions: azure.mgmt.resource.templatespecs.v2019_06_01_preview.aio.operations.TemplateSpecVersionsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription Id which forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = TemplateSpecsClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.template_specs = TemplateSpecsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.template_spec_versions = TemplateSpecVersionsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "TemplateSpecsClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
