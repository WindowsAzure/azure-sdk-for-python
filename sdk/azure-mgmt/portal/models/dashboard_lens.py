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


class DashboardLens(Model):
    """A dashboard lens.

    All required parameters must be populated in order to send to Azure.

    :param order: Required. The lens order.
    :type order: int
    :param parts: Required. The dashboard parts.
    :type parts: dict[str, ~microsoft.portal.models.DashboardParts]
    :param metadata: The dashboard len's metadata.
    :type metadata: dict[str, object]
    """

    _validation = {
        'order': {'required': True},
        'parts': {'required': True},
    }

    _attribute_map = {
        'order': {'key': 'order', 'type': 'int'},
        'parts': {'key': 'parts', 'type': '{DashboardParts}'},
        'metadata': {'key': 'metadata', 'type': '{object}'},
    }

    def __init__(self, **kwargs):
        super(DashboardLens, self).__init__(**kwargs)
        self.order = kwargs.get('order', None)
        self.parts = kwargs.get('parts', None)
        self.metadata = kwargs.get('metadata', None)
