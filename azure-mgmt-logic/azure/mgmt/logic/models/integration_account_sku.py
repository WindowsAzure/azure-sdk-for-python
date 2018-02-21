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


class IntegrationAccountSku(Model):
    """The integration account sku.

    :param name: The sku name. Possible values include: 'NotSpecified',
     'Free', 'Standard'
    :type name: str or ~azure.mgmt.logic.models.IntegrationAccountSkuName
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'IntegrationAccountSkuName'},
    }

    def __init__(self, name):
        super(IntegrationAccountSku, self).__init__()
        self.name = name
