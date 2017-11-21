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


class IntegrationRuntimeSsisProperties(Model):
    """SSIS properties for managed integration runtime.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param catalog_info: Catalog information for managed dedicated integration
     runtime.
    :type catalog_info:
     ~azure.mgmt.datafactory.models.IntegrationRuntimeSsisCatalogInfo
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'catalog_info': {'key': 'catalogInfo', 'type': 'IntegrationRuntimeSsisCatalogInfo'},
    }

    def __init__(self, additional_properties=None, catalog_info=None):
        self.additional_properties = additional_properties
        self.catalog_info = catalog_info
