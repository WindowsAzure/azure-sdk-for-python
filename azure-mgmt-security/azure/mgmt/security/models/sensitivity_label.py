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


class SensitivityLabel(Model):
    """The sensitivity label.

    :param display_name: The name of the sensitivity label.
    :type display_name: str
    :param order: The order of the sensitivity label.
    :type order: float
    :param enabled: Indicates whether the label is enabled or not.
    :type enabled: bool
    """

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'order': {'key': 'order', 'type': 'float'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(SensitivityLabel, self).__init__(**kwargs)
        self.display_name = kwargs.get('display_name', None)
        self.order = kwargs.get('order', None)
        self.enabled = kwargs.get('enabled', None)
