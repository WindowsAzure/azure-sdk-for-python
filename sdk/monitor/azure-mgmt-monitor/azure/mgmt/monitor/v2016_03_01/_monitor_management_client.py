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

from ._configuration import MonitorManagementClientConfiguration
from .operations import AlertRuleIncidentsOperations
from .operations import AlertRulesOperations
from .operations import LogProfilesOperations
from .operations import MetricDefinitionsOperations
from . import models


class MonitorManagementClient(object):
    """Monitor Management Client.

    :ivar alert_rule_incidents: AlertRuleIncidentsOperations operations
    :vartype alert_rule_incidents: $(python-base-namespace).v2016_03_01.operations.AlertRuleIncidentsOperations
    :ivar alert_rules: AlertRulesOperations operations
    :vartype alert_rules: $(python-base-namespace).v2016_03_01.operations.AlertRulesOperations
    :ivar log_profiles: LogProfilesOperations operations
    :vartype log_profiles: $(python-base-namespace).v2016_03_01.operations.LogProfilesOperations
    :ivar metric_definitions: MetricDefinitionsOperations operations
    :vartype metric_definitions: $(python-base-namespace).v2016_03_01.operations.MetricDefinitionsOperations
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
        self._config = MonitorManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.alert_rule_incidents = AlertRuleIncidentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.alert_rules = AlertRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.log_profiles = LogProfilesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.metric_definitions = MetricDefinitionsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> MonitorManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
