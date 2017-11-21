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


class HDInsightMapReduceActivity(ExecutionActivity):
    """HDInsight MapReduce activity type.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param name: Activity name.
    :type name: str
    :param description: Activity description.
    :type description: str
    :param depends_on: Activity depends on condition.
    :type depends_on: list[~azure.mgmt.datafactory.models.ActivityDependency]
    :param type: Constant filled by server.
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
    :param class_name: Class name. Type: string (or Expression with resultType
     string).
    :type class_name: object
    :param jar_file_path: Jar path. Type: string (or Expression with
     resultType string).
    :type jar_file_path: object
    :param jar_linked_service: Jar linked service reference.
    :type jar_linked_service:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param jar_libs: Jar libs.
    :type jar_libs: list[object]
    :param defines: Allows user to specify defines for the MapReduce job
     request.
    :type defines: dict[str, object]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'class_name': {'required': True},
        'jar_file_path': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'policy': {'key': 'policy', 'type': 'ActivityPolicy'},
        'storage_linked_services': {'key': 'typeProperties.storageLinkedServices', 'type': '[LinkedServiceReference]'},
        'arguments': {'key': 'typeProperties.arguments', 'type': '[object]'},
        'get_debug_info': {'key': 'typeProperties.getDebugInfo', 'type': 'str'},
        'class_name': {'key': 'typeProperties.className', 'type': 'object'},
        'jar_file_path': {'key': 'typeProperties.jarFilePath', 'type': 'object'},
        'jar_linked_service': {'key': 'typeProperties.jarLinkedService', 'type': 'LinkedServiceReference'},
        'jar_libs': {'key': 'typeProperties.jarLibs', 'type': '[object]'},
        'defines': {'key': 'typeProperties.defines', 'type': '{object}'},
    }

    def __init__(self, name, class_name, jar_file_path, additional_properties=None, description=None, depends_on=None, linked_service_name=None, policy=None, storage_linked_services=None, arguments=None, get_debug_info=None, jar_linked_service=None, jar_libs=None, defines=None):
        super(HDInsightMapReduceActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on, linked_service_name=linked_service_name, policy=policy)
        self.storage_linked_services = storage_linked_services
        self.arguments = arguments
        self.get_debug_info = get_debug_info
        self.class_name = class_name
        self.jar_file_path = jar_file_path
        self.jar_linked_service = jar_linked_service
        self.jar_libs = jar_libs
        self.defines = defines
        self.type = 'HDInsightMapReduce'
