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


class IoTSecurityAlertedDevicesList(Model):
    """List of devices with the count of raised alerts.

    All required parameters must be populated in order to send to Azure.

    :param value: Required. List of aggregated alerts data
    :type value: list[~azure.mgmt.security.models.IoTSecurityAlertedDevice]
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[IoTSecurityAlertedDevice]'},
    }

    def __init__(self, *, value, **kwargs) -> None:
        super(IoTSecurityAlertedDevicesList, self).__init__(**kwargs)
        self.value = value
