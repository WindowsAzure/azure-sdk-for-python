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

from msrest.serialization import Model


class ConnectivityIssue(Model):
    """Information about an issue encountered in the process of checking for
    connectivity.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar origin: The origin of the issue. Possible values include: 'Local',
     'Inbound', 'Outbound'
    :vartype origin: str or ~azure.mgmt.network.v2017_06_01.models.Origin
    :ivar severity: The severity of the issue. Possible values include:
     'Error', 'Warning'
    :vartype severity: str or ~azure.mgmt.network.v2017_06_01.models.Severity
    :ivar type: The type of issue. Possible values include: 'Unknown',
     'AgentStopped', 'GuestFirewall', 'DnsResolution', 'SocketBind',
     'NetworkSecurityRule', 'UserDefinedRoute', 'PortThrottled', 'Platform'
    :vartype type: str or ~azure.mgmt.network.v2017_06_01.models.IssueType
    :ivar context: Provides additional context on the issue.
    :vartype context: list[dict[str, str]]
    """

    _validation = {
        'origin': {'readonly': True},
        'severity': {'readonly': True},
        'type': {'readonly': True},
        'context': {'readonly': True},
    }

    _attribute_map = {
        'origin': {'key': 'origin', 'type': 'str'},
        'severity': {'key': 'severity', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'context': {'key': 'context', 'type': '[{str}]'},
    }

    def __init__(self, **kwargs):
        super(ConnectivityIssue, self).__init__(**kwargs)
        self.origin = None
        self.severity = None
        self.type = None
        self.context = None
