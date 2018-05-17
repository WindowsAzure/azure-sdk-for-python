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

from .proxy_resource_py3 import ProxyResource


class DatabaseSecurityAlertPolicy(ProxyResource):
    """Contains information about a database Threat Detection policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: The geo-location where the resource lives
    :type location: str
    :ivar kind: Resource kind.
    :vartype kind: str
    :param state: Required. Specifies the state of the policy. If state is
     Enabled, storageEndpoint and storageAccountAccessKey are required.
     Possible values include: 'New', 'Enabled', 'Disabled'
    :type state: str or ~azure.mgmt.sql.models.SecurityAlertPolicyState
    :param disabled_alerts: Specifies the semicolon-separated list of alerts
     that are disabled, or empty string to disable no alerts. Possible values:
     Sql_Injection; Sql_Injection_Vulnerability; Access_Anomaly; Usage_Anomaly.
    :type disabled_alerts: str
    :param email_addresses: Specifies the semicolon-separated list of e-mail
     addresses to which the alert is sent.
    :type email_addresses: str
    :param email_account_admins: Specifies that the alert is sent to the
     account administrators. Possible values include: 'Enabled', 'Disabled'
    :type email_account_admins: str or
     ~azure.mgmt.sql.models.SecurityAlertPolicyEmailAccountAdmins
    :param storage_endpoint: Specifies the blob storage endpoint (e.g.
     https://MyAccount.blob.core.windows.net). This blob storage will hold all
     Threat Detection audit logs. If state is Enabled, storageEndpoint is
     required.
    :type storage_endpoint: str
    :param storage_account_access_key: Specifies the identifier key of the
     Threat Detection audit storage account. If state is Enabled,
     storageAccountAccessKey is required.
    :type storage_account_access_key: str
    :param retention_days: Specifies the number of days to keep in the Threat
     Detection audit logs.
    :type retention_days: int
    :param use_server_default: Specifies whether to use the default server
     policy. Possible values include: 'Enabled', 'Disabled'
    :type use_server_default: str or
     ~azure.mgmt.sql.models.SecurityAlertPolicyUseServerDefault
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'readonly': True},
        'state': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'SecurityAlertPolicyState'},
        'disabled_alerts': {'key': 'properties.disabledAlerts', 'type': 'str'},
        'email_addresses': {'key': 'properties.emailAddresses', 'type': 'str'},
        'email_account_admins': {'key': 'properties.emailAccountAdmins', 'type': 'SecurityAlertPolicyEmailAccountAdmins'},
        'storage_endpoint': {'key': 'properties.storageEndpoint', 'type': 'str'},
        'storage_account_access_key': {'key': 'properties.storageAccountAccessKey', 'type': 'str'},
        'retention_days': {'key': 'properties.retentionDays', 'type': 'int'},
        'use_server_default': {'key': 'properties.useServerDefault', 'type': 'SecurityAlertPolicyUseServerDefault'},
    }

    def __init__(self, *, state, location: str=None, disabled_alerts: str=None, email_addresses: str=None, email_account_admins=None, storage_endpoint: str=None, storage_account_access_key: str=None, retention_days: int=None, use_server_default=None, **kwargs) -> None:
        super(DatabaseSecurityAlertPolicy, self).__init__(**kwargs)
        self.location = location
        self.kind = None
        self.state = state
        self.disabled_alerts = disabled_alerts
        self.email_addresses = email_addresses
        self.email_account_admins = email_account_admins
        self.storage_endpoint = storage_endpoint
        self.storage_account_access_key = storage_account_access_key
        self.retention_days = retention_days
        self.use_server_default = use_server_default
