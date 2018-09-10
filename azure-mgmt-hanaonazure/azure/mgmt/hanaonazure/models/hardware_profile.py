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


class HardwareProfile(Model):
    """Specifies the hardware settings for the HANA instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar hardware_type: Name of the hardware type (vendor and/or their
     product name). Possible values include: 'Cisco_UCS', 'HPE'
    :vartype hardware_type: str or
     ~azure.mgmt.hanaonazure.models.HanaHardwareTypeNamesEnum
    :ivar hana_instance_size: Specifies the HANA instance SKU. Possible values
     include: 'S72m', 'S144m', 'S72', 'S144', 'S192', 'S192m', 'S192xm',
     'S384', 'S384m', 'S384xm', 'S384xxm', 'S576m', 'S576xm', 'S768', 'S768m',
     'S768xm', 'S960m'
    :vartype hana_instance_size: str or
     ~azure.mgmt.hanaonazure.models.HanaInstanceSizeNamesEnum
    """

    _validation = {
        'hardware_type': {'readonly': True},
        'hana_instance_size': {'readonly': True},
    }

    _attribute_map = {
        'hardware_type': {'key': 'hardwareType', 'type': 'str'},
        'hana_instance_size': {'key': 'hanaInstanceSize', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(HardwareProfile, self).__init__(**kwargs)
        self.hardware_type = None
        self.hana_instance_size = None
