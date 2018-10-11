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


class ExtendedDatabaseBlobAuditingPolicy(ProxyResource):
    """An extended database blob auditing policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param predicate_expression: Specifies condition of where clause when
     creating an audit.
    :type predicate_expression: str
    :param state: Required. Specifies the state of the policy. If state is
     Enabled, storageEndpoint and storageAccountAccessKey are required.
     Possible values include: 'Enabled', 'Disabled'
    :type state: str or ~azure.mgmt.sql.models.BlobAuditingPolicyState
    :param storage_endpoint: Specifies the blob storage endpoint (e.g.
     https://MyAccount.blob.core.windows.net). If state is Enabled,
     storageEndpoint is required.
    :type storage_endpoint: str
    :param storage_account_access_key: Specifies the identifier key of the
     auditing storage account. If state is Enabled, storageAccountAccessKey is
     required.
    :type storage_account_access_key: str
    :param retention_days: Specifies the number of days to keep in the audit
     logs.
    :type retention_days: int
    :param audit_actions_and_groups: Specifies the Actions-Groups and Actions
     to audit.
     The recommended set of action groups to use is the following combination -
     this will audit all the queries and stored procedures executed against the
     database, as well as successful and failed logins:
     BATCH_COMPLETED_GROUP,
     SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP,
     FAILED_DATABASE_AUTHENTICATION_GROUP.
     This above combination is also the set that is configured by default when
     enabling auditing from the Azure portal.
     The supported action groups to audit are (note: choose only specific
     groups that cover your auditing needs. Using unnecessary groups could lead
     to very large quantities of audit records):
     APPLICATION_ROLE_CHANGE_PASSWORD_GROUP
     BACKUP_RESTORE_GROUP
     DATABASE_LOGOUT_GROUP
     DATABASE_OBJECT_CHANGE_GROUP
     DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP
     DATABASE_OBJECT_PERMISSION_CHANGE_GROUP
     DATABASE_OPERATION_GROUP
     DATABASE_PERMISSION_CHANGE_GROUP
     DATABASE_PRINCIPAL_CHANGE_GROUP
     DATABASE_PRINCIPAL_IMPERSONATION_GROUP
     DATABASE_ROLE_MEMBER_CHANGE_GROUP
     FAILED_DATABASE_AUTHENTICATION_GROUP
     SCHEMA_OBJECT_ACCESS_GROUP
     SCHEMA_OBJECT_CHANGE_GROUP
     SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP
     SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP
     SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP
     USER_CHANGE_PASSWORD_GROUP
     BATCH_STARTED_GROUP
     BATCH_COMPLETED_GROUP
     These are groups that cover all sql statements and stored procedures
     executed against the database, and should not be used in combination with
     other groups as this will result in duplicate audit logs.
     For more information, see [Database-Level Audit Action
     Groups](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions#database-level-audit-action-groups).
     For Database auditing policy, specific Actions can also be specified (note
     that Actions cannot be specified for Server auditing policy). The
     supported actions to audit are:
     SELECT
     UPDATE
     INSERT
     DELETE
     EXECUTE
     RECEIVE
     REFERENCES
     The general form for defining an action to be audited is:
     <action> ON <object> BY <principal>
     Note that <object> in the above format can refer to an object like a
     table, view, or stored procedure, or an entire database or schema. For the
     latter cases, the forms DATABASE::<db_name> and SCHEMA::<schema_name> are
     used, respectively.
     For example:
     SELECT on dbo.myTable by public
     SELECT on DATABASE::myDatabase by public
     SELECT on SCHEMA::mySchema by public
     For more information, see [Database-Level Audit
     Actions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions#database-level-audit-actions)
    :type audit_actions_and_groups: list[str]
    :param storage_account_subscription_id: Specifies the blob storage
     subscription Id.
    :type storage_account_subscription_id: str
    :param is_storage_secondary_key_in_use: Specifies whether
     storageAccountAccessKey value is the storage's secondary key.
    :type is_storage_secondary_key_in_use: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'state': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'predicate_expression': {'key': 'properties.predicateExpression', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'BlobAuditingPolicyState'},
        'storage_endpoint': {'key': 'properties.storageEndpoint', 'type': 'str'},
        'storage_account_access_key': {'key': 'properties.storageAccountAccessKey', 'type': 'str'},
        'retention_days': {'key': 'properties.retentionDays', 'type': 'int'},
        'audit_actions_and_groups': {'key': 'properties.auditActionsAndGroups', 'type': '[str]'},
        'storage_account_subscription_id': {'key': 'properties.storageAccountSubscriptionId', 'type': 'str'},
        'is_storage_secondary_key_in_use': {'key': 'properties.isStorageSecondaryKeyInUse', 'type': 'bool'},
    }

    def __init__(self, *, state, predicate_expression: str=None, storage_endpoint: str=None, storage_account_access_key: str=None, retention_days: int=None, audit_actions_and_groups=None, storage_account_subscription_id: str=None, is_storage_secondary_key_in_use: bool=None, **kwargs) -> None:
        super(ExtendedDatabaseBlobAuditingPolicy, self).__init__(**kwargs)
        self.predicate_expression = predicate_expression
        self.state = state
        self.storage_endpoint = storage_endpoint
        self.storage_account_access_key = storage_account_access_key
        self.retention_days = retention_days
        self.audit_actions_and_groups = audit_actions_and_groups
        self.storage_account_subscription_id = storage_account_subscription_id
        self.is_storage_secondary_key_in_use = is_storage_secondary_key_in_use
