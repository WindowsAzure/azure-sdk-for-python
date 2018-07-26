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


class CreateVirtualNetworkRuleWithAccountParameters(Model):
    """The parameters used to create a new virtual network rule while creating a
    new Data Lake Store account.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The unique name of the virtual network rule to
     create.
    :type name: str
    :param subnet_id: Required. The resource identifier for the subnet.
    :type subnet_id: str
    """

    _validation = {
        'name': {'required': True},
        'subnet_id': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CreateVirtualNetworkRuleWithAccountParameters, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.subnet_id = kwargs.get('subnet_id', None)
