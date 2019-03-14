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


class EnvironmentSettingCreationParameters(Model):
    """Settings related to creating an environment setting.

    All required parameters must be populated in order to send to Azure.

    :param resource_setting_creation_parameters: Required. The resource
     specific settings
    :type resource_setting_creation_parameters:
     ~azure.mgmt.labservices.models.ResourceSettingCreationParameters
    """

    _validation = {
        'resource_setting_creation_parameters': {'required': True},
    }

    _attribute_map = {
        'resource_setting_creation_parameters': {'key': 'resourceSettingCreationParameters', 'type': 'ResourceSettingCreationParameters'},
    }

    def __init__(self, *, resource_setting_creation_parameters, **kwargs) -> None:
        super(EnvironmentSettingCreationParameters, self).__init__(**kwargs)
        self.resource_setting_creation_parameters = resource_setting_creation_parameters
