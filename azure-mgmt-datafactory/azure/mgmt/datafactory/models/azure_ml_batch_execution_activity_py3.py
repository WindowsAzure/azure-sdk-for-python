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


class AzureMLBatchExecutionActivity(ExecutionActivity):
    """Azure ML Batch Execution activity.

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
    :param global_parameters: Key,Value pairs to be passed to the Azure ML
     Batch Execution Service endpoint. Keys must match the names of web service
     parameters defined in the published Azure ML web service. Values will be
     passed in the GlobalParameters property of the Azure ML batch execution
     request.
    :type global_parameters: dict[str, object]
    :param web_service_outputs: Key,Value pairs, mapping the names of Azure ML
     endpoint's Web Service Outputs to AzureMLWebServiceFile objects specifying
     the output Blob locations. This information will be passed in the
     WebServiceOutputs property of the Azure ML batch execution request.
    :type web_service_outputs: dict[str,
     ~azure.mgmt.datafactory.models.AzureMLWebServiceFile]
    :param web_service_inputs: Key,Value pairs, mapping the names of Azure ML
     endpoint's Web Service Inputs to AzureMLWebServiceFile objects specifying
     the input Blob locations.. This information will be passed in the
     WebServiceInputs property of the Azure ML batch execution request.
    :type web_service_inputs: dict[str,
     ~azure.mgmt.datafactory.models.AzureMLWebServiceFile]
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
        'global_parameters': {'key': 'typeProperties.globalParameters', 'type': '{object}'},
        'web_service_outputs': {'key': 'typeProperties.webServiceOutputs', 'type': '{AzureMLWebServiceFile}'},
        'web_service_inputs': {'key': 'typeProperties.webServiceInputs', 'type': '{AzureMLWebServiceFile}'},
    }

    def __init__(self, *, name: str, additional_properties=None, description: str=None, depends_on=None, user_properties=None, linked_service_name=None, policy=None, global_parameters=None, web_service_outputs=None, web_service_inputs=None, **kwargs) -> None:
        super(AzureMLBatchExecutionActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on, user_properties=user_properties, linked_service_name=linked_service_name, policy=policy, **kwargs)
        self.global_parameters = global_parameters
        self.web_service_outputs = web_service_outputs
        self.web_service_inputs = web_service_inputs
        self.type = 'AzureMLBatchExecution'
