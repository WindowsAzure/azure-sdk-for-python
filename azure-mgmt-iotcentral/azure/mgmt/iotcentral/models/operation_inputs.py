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


class OperationInputs(Model):
    """Input values.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the IoT Central application instance to
     check.
    :type name: str
    :param type: The type of the IoT Central resource to query. Possible
     values include: 'IoTApps'. Default value: "IoTApps" .
    :type type: str or ~azure.mgmt.iotcentral.models.enum
    """

    _validation = {
        'name': {'required': True, 'pattern': r'^[a-z0-9-]{1,63}$'},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OperationInputs, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.type = kwargs.get('type', "IoTApps")
