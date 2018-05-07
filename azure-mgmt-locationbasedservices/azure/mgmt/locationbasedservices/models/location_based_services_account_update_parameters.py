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


class LocationBasedServicesAccountUpdateParameters(Model):
    """Parameters used to update an existing Location Based Services Account.

    :param tags: Gets or sets a list of key value pairs that describe the
     resource. These tags can be used in viewing and grouping this resource
     (across resource groups). A maximum of 15 tags can be provided for a
     resource. Each tag must have a key no greater than 128 characters and
     value no greater than 256 characters.
    :type tags: dict[str, str]
    :param sku: The SKU of this account.
    :type sku: ~azure.mgmt.locationbasedservices.models.Sku
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
    }

    def __init__(self, tags=None, sku=None):
        super(LocationBasedServicesAccountUpdateParameters, self).__init__()
        self.tags = tags
        self.sku = sku
