# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

from ._configuration import AzureCommunicationSMSServiceConfiguration
from .operations import SmsOperations
from . import models


class AzureCommunicationSMSService(object):
    """Azure Communication SMS Service.

    :ivar sms: SmsOperations operations
    :vartype sms: azure.communication.sms.operations.SmsOperations
    :param endpoint: The endpoint of the Azure Communication resource.
    :type endpoint: str
    """

    def __init__(
        self,
        endpoint,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        base_url = '{endpoint}'
        self._config = AzureCommunicationSMSServiceConfiguration(endpoint, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.sms = SmsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> AzureCommunicationSMSService
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
