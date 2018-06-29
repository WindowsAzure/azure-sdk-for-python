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


class GetMetadataActivity(ExecutionActivity):
    """Activity to get metadata of dataset.

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
    :param type: Required. Constant filled by server.
    :type type: str
    :param linked_service_name: Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param policy: Activity policy.
    :type policy: ~azure.mgmt.datafactory.models.ActivityPolicy
    :param dataset: Required. GetMetadata activity dataset reference.
    :type dataset: ~azure.mgmt.datafactory.models.DatasetReference
    :param field_list: Fields of metadata to get from dataset.
    :type field_list: list[object]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'dataset': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'policy': {'key': 'policy', 'type': 'ActivityPolicy'},
        'dataset': {'key': 'typeProperties.dataset', 'type': 'DatasetReference'},
        'field_list': {'key': 'typeProperties.fieldList', 'type': '[object]'},
    }

    def __init__(self, *, name: str, dataset, additional_properties=None, description: str=None, depends_on=None, linked_service_name=None, policy=None, field_list=None, **kwargs) -> None:
        super(GetMetadataActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on, linked_service_name=linked_service_name, policy=policy, **kwargs)
        self.dataset = dataset
        self.field_list = field_list
        self.type = 'GetMetadata'
