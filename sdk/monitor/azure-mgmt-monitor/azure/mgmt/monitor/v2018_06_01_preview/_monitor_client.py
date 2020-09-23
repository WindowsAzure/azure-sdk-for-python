# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential

from ._configuration import MonitorClientConfiguration
from .operations import GuestDiagnosticsSettingsAssociationOperations
from .operations import GuestDiagnosticsSettingsOperations
from . import models


class MonitorClient(object):
    """Monitor Management Client.

    :ivar guest_diagnostics_settings_association: GuestDiagnosticsSettingsAssociationOperations operations
    :vartype guest_diagnostics_settings_association: $(python-base-namespace).v2018_06_01_preview.operations.GuestDiagnosticsSettingsAssociationOperations
    :ivar guest_diagnostics_settings: GuestDiagnosticsSettingsOperations operations
    :vartype guest_diagnostics_settings: $(python-base-namespace).v2018_06_01_preview.operations.GuestDiagnosticsSettingsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The Azure subscription Id.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = MonitorClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.guest_diagnostics_settings_association = GuestDiagnosticsSettingsAssociationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.guest_diagnostics_settings = GuestDiagnosticsSettingsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> MonitorClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
