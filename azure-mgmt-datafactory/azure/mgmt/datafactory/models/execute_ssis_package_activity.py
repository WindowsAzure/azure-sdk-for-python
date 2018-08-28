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


class ExecuteSSISPackageActivity(ExecutionActivity):
    """Execute SSIS package activity.

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
    :param package_location: Required. SSIS package location.
    :type package_location: ~azure.mgmt.datafactory.models.SSISPackageLocation
    :param runtime: Specifies the runtime to execute SSIS package. Possible
     values include: 'x64', 'x86'
    :type runtime: str or ~azure.mgmt.datafactory.models.SSISExecutionRuntime
    :param logging_level: The logging level of SSIS package execution.
    :type logging_level: str
    :param environment_path: The environment path to execute the SSIS package.
    :type environment_path: str
    :param connect_via: Required. The integration runtime reference.
    :type connect_via:
     ~azure.mgmt.datafactory.models.IntegrationRuntimeReference
    :param project_parameters: The project level parameters to execute the
     SSIS package.
    :type project_parameters: dict[str,
     ~azure.mgmt.datafactory.models.SSISExecutionParameter]
    :param package_parameters: The package level parameters to execute the
     SSIS package.
    :type package_parameters: dict[str,
     ~azure.mgmt.datafactory.models.SSISExecutionParameter]
    :param project_connection_managers: The project level connection managers
     to execute the SSIS package.
    :type project_connection_managers: dict[str, dict[str,
     ~azure.mgmt.datafactory.models.SSISExecutionParameter]]
    :param package_connection_managers: The package level connection managers
     to execute the SSIS package.
    :type package_connection_managers: dict[str, dict[str,
     ~azure.mgmt.datafactory.models.SSISExecutionParameter]]
    :param property_overrides: The property overrides to execute the SSIS
     package.
    :type property_overrides: dict[str,
     ~azure.mgmt.datafactory.models.SSISPropertyOverride]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'package_location': {'required': True},
        'connect_via': {'required': True},
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
        'package_location': {'key': 'typeProperties.packageLocation', 'type': 'SSISPackageLocation'},
        'runtime': {'key': 'typeProperties.runtime', 'type': 'str'},
        'logging_level': {'key': 'typeProperties.loggingLevel', 'type': 'str'},
        'environment_path': {'key': 'typeProperties.environmentPath', 'type': 'str'},
        'connect_via': {'key': 'typeProperties.connectVia', 'type': 'IntegrationRuntimeReference'},
        'project_parameters': {'key': 'typeProperties.projectParameters', 'type': '{SSISExecutionParameter}'},
        'package_parameters': {'key': 'typeProperties.packageParameters', 'type': '{SSISExecutionParameter}'},
        'project_connection_managers': {'key': 'typeProperties.projectConnectionManagers', 'type': '{{SSISExecutionParameter}}'},
        'package_connection_managers': {'key': 'typeProperties.packageConnectionManagers', 'type': '{{SSISExecutionParameter}}'},
        'property_overrides': {'key': 'typeProperties.propertyOverrides', 'type': '{SSISPropertyOverride}'},
    }

    def __init__(self, **kwargs):
        super(ExecuteSSISPackageActivity, self).__init__(**kwargs)
        self.package_location = kwargs.get('package_location', None)
        self.runtime = kwargs.get('runtime', None)
        self.logging_level = kwargs.get('logging_level', None)
        self.environment_path = kwargs.get('environment_path', None)
        self.connect_via = kwargs.get('connect_via', None)
        self.project_parameters = kwargs.get('project_parameters', None)
        self.package_parameters = kwargs.get('package_parameters', None)
        self.project_connection_managers = kwargs.get('project_connection_managers', None)
        self.package_connection_managers = kwargs.get('package_connection_managers', None)
        self.property_overrides = kwargs.get('property_overrides', None)
        self.type = 'ExecuteSSISPackage'
