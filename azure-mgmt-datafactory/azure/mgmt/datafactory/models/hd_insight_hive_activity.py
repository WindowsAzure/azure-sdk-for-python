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

from .execution_activity import ExecutionActivity


class HDInsightHiveActivity(ExecutionActivity):
    """HDInsight Hive activity type.

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
    :param storage_linked_services: Storage linked service references.
    :type storage_linked_services:
     list[~azure.mgmt.datafactory.models.LinkedServiceReference]
    :param arguments: User specified arguments to HDInsightActivity.
    :type arguments: list[object]
    :param get_debug_info: Debug info option. Possible values include: 'None',
     'Always', 'Failure'
    :type get_debug_info: str or
     ~azure.mgmt.datafactory.models.HDInsightActivityDebugInfoOption
    :param script_path: Script path. Type: string (or Expression with
     resultType string).
    :type script_path: object
    :param script_linked_service: Script linked service reference.
    :type script_linked_service:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param defines: Allows user to specify defines for Hive job request.
    :type defines: dict[str, object]
    :param variables: User specified arguments under hivevar namespace.
    :type variables: list[object]
    :param query_timeout: Query timeout value (in minutes).  Effective when
     the HDInsight culster is with ESP (Enterprise Security Package)
    :type query_timeout: int
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
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
        'storage_linked_services': {'key': 'typeProperties.storageLinkedServices', 'type': '[LinkedServiceReference]'},
        'arguments': {'key': 'typeProperties.arguments', 'type': '[object]'},
        'get_debug_info': {'key': 'typeProperties.getDebugInfo', 'type': 'str'},
        'script_path': {'key': 'typeProperties.scriptPath', 'type': 'object'},
        'script_linked_service': {'key': 'typeProperties.scriptLinkedService', 'type': 'LinkedServiceReference'},
        'defines': {'key': 'typeProperties.defines', 'type': '{object}'},
        'variables': {'key': 'typeProperties.variables', 'type': '[object]'},
        'query_timeout': {'key': 'typeProperties.queryTimeout', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(HDInsightHiveActivity, self).__init__(**kwargs)
        self.storage_linked_services = kwargs.get('storage_linked_services', None)
        self.arguments = kwargs.get('arguments', None)
        self.get_debug_info = kwargs.get('get_debug_info', None)
        self.script_path = kwargs.get('script_path', None)
        self.script_linked_service = kwargs.get('script_linked_service', None)
        self.defines = kwargs.get('defines', None)
        self.variables = kwargs.get('variables', None)
        self.query_timeout = kwargs.get('query_timeout', None)
        self.type = 'HDInsightHive'
