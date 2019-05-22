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

from .execution_activity_py3 import ExecutionActivity


class SqlServerStoredProcedureActivity(ExecutionActivity):
    """SQL stored procedure activity type.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param name: Required. Activity name.
    :type name: str
    :param description: Activity description.
    :type description: str
    :param depends_on: Activity depends on condition.
    :type depends_on: list[~azure.mgmt.datafactory.models.ActivityDependency]
    :param user_properties: Activity user properties.
    :type user_properties: list[~azure.mgmt.datafactory.models.UserProperty]
    :param type: Required. Constant filled by server.
    :type type: str
    :param linked_service_name: Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param policy: Activity policy.
    :type policy: ~azure.mgmt.datafactory.models.ActivityPolicy
    :param stored_procedure_name: Required. Stored procedure name. Type:
     string (or Expression with resultType string).
    :type stored_procedure_name: object
    :param stored_procedure_parameters: Value and type setting for stored
     procedure parameters. Example: "{Parameter1: {value: "1", type: "int"}}".
    :type stored_procedure_parameters: dict[str,
     ~azure.mgmt.datafactory.models.StoredProcedureParameter]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'stored_procedure_name': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'user_properties': {'key': 'userProperties', 'type': '[UserProperty]'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'policy': {'key': 'policy', 'type': 'ActivityPolicy'},
        'stored_procedure_name': {'key': 'typeProperties.storedProcedureName', 'type': 'object'},
        'stored_procedure_parameters': {'key': 'typeProperties.storedProcedureParameters', 'type': '{StoredProcedureParameter}'},
    }

    def __init__(self, *, name: str, stored_procedure_name, additional_properties=None, description: str=None, depends_on=None, user_properties=None, linked_service_name=None, policy=None, stored_procedure_parameters=None, **kwargs) -> None:
        super(SqlServerStoredProcedureActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on, user_properties=user_properties, linked_service_name=linked_service_name, policy=policy, **kwargs)
        self.stored_procedure_name = stored_procedure_name
        self.stored_procedure_parameters = stored_procedure_parameters
        self.type = 'SqlServerStoredProcedure'
