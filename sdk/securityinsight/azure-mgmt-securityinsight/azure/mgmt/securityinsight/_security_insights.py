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

from ._configuration import SecurityInsightsConfiguration
from .operations import Operations
from .operations import AlertRulesOperations
from .operations import ActionsOperations
from .operations import AlertRuleTemplatesOperations
from .operations import BookmarksOperations
from .operations import DataConnectorsOperations
from .operations import IncidentsOperations
from .operations import IncidentCommentsOperations
from . import models


class SecurityInsights(object):
    """API spec for Microsoft.SecurityInsights (Azure Security Insights) resource provider.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.securityinsight.operations.Operations
    :ivar alert_rules: AlertRulesOperations operations
    :vartype alert_rules: azure.mgmt.securityinsight.operations.AlertRulesOperations
    :ivar actions: ActionsOperations operations
    :vartype actions: azure.mgmt.securityinsight.operations.ActionsOperations
    :ivar alert_rule_templates: AlertRuleTemplatesOperations operations
    :vartype alert_rule_templates: azure.mgmt.securityinsight.operations.AlertRuleTemplatesOperations
    :ivar bookmarks: BookmarksOperations operations
    :vartype bookmarks: azure.mgmt.securityinsight.operations.BookmarksOperations
    :ivar data_connectors: DataConnectorsOperations operations
    :vartype data_connectors: azure.mgmt.securityinsight.operations.DataConnectorsOperations
    :ivar incidents: IncidentsOperations operations
    :vartype incidents: azure.mgmt.securityinsight.operations.IncidentsOperations
    :ivar incident_comments: IncidentCommentsOperations operations
    :vartype incident_comments: azure.mgmt.securityinsight.operations.IncidentCommentsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: Azure subscription ID.
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
        self._config = SecurityInsightsConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.alert_rules = AlertRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.actions = ActionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.alert_rule_templates = AlertRuleTemplatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.bookmarks = BookmarksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.data_connectors = DataConnectorsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.incidents = IncidentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.incident_comments = IncidentCommentsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> SecurityInsights
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
