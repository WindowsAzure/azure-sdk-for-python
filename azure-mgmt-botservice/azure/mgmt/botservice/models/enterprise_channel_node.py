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


class EnterpriseChannelNode(Model):
    """The properties specific to an Enterprise Channel Node.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Id of Enterprise Channel Node
    :type id: str
    :param state: The current state of the Enterprise Channel Node
    :type state: str
    :param name: Required. The name of the Enterprise Channel Node
    :type name: str
    :param azure_sku: Required. The sku of the Enterprise Channel Node
    :type azure_sku: str
    :param azure_location: Required. The location of the Enterprise Channel
     Node
    :type azure_location: str
    """

    _validation = {
        'id': {'required': True},
        'name': {'required': True},
        'azure_sku': {'required': True},
        'azure_location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'azure_sku': {'key': 'azureSku', 'type': 'str'},
        'azure_location': {'key': 'azureLocation', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EnterpriseChannelNode, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.state = kwargs.get('state', None)
        self.name = kwargs.get('name', None)
        self.azure_sku = kwargs.get('azure_sku', None)
        self.azure_location = kwargs.get('azure_location', None)
