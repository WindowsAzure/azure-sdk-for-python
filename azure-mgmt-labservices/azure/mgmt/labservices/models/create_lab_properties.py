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


class CreateLabProperties(Model):
    """Properties for creating a managed lab and a default environment setting.

    All required parameters must be populated in order to send to Azure.

    :param environment_setting_creation_parameters: Settings related to
     creating an environment setting
    :type environment_setting_creation_parameters:
     ~azure.mgmt.labservices.models.EnvironmentSettingCreationParameters
    :param lab_creation_parameters: Required. Settings related to creating a
     lab
    :type lab_creation_parameters:
     ~azure.mgmt.labservices.models.LabCreationParameters
    :param name: Required. The name of the resource
    :type name: str
    :param location: The location of the resource
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    """

    _validation = {
        'lab_creation_parameters': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'environment_setting_creation_parameters': {'key': 'environmentSettingCreationParameters', 'type': 'EnvironmentSettingCreationParameters'},
        'lab_creation_parameters': {'key': 'labCreationParameters', 'type': 'LabCreationParameters'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(CreateLabProperties, self).__init__(**kwargs)
        self.environment_setting_creation_parameters = kwargs.get('environment_setting_creation_parameters', None)
        self.lab_creation_parameters = kwargs.get('lab_creation_parameters', None)
        self.name = kwargs.get('name', None)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
