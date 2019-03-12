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


class BaseImageTrigger(Model):
    """The trigger based on base image dependency.

    All required parameters must be populated in order to send to Azure.

    :param base_image_trigger_type: Required. The type of the auto trigger for
     base image dependency updates. Possible values include: 'All', 'Runtime'
    :type base_image_trigger_type: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.BaseImageTriggerType
    :param status: The current status of trigger. Possible values include:
     'Disabled', 'Enabled'
    :type status: str or
     ~azure.mgmt.containerregistry.v2018_09_01.models.TriggerStatus
    :param name: Required. The name of the trigger.
    :type name: str
    """

    _validation = {
        'base_image_trigger_type': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'base_image_trigger_type': {'key': 'baseImageTriggerType', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(BaseImageTrigger, self).__init__(**kwargs)
        self.base_image_trigger_type = kwargs.get('base_image_trigger_type', None)
        self.status = kwargs.get('status', None)
        self.name = kwargs.get('name', None)
