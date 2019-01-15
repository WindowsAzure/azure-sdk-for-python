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


class InformationType(Model):
    """The information type.

    :param display_name: The name of the information type.
    :type display_name: str
    :param order: The order of the information type.
    :type order: float
    :param recommended_label_id: The recommended label id to be associated
     with this information type.
    :type recommended_label_id: str
    :param enabled: Indicates whether the information type is enabled or not.
    :type enabled: bool
    :param custom: Indicates whether the information type is custom or not.
    :type custom: bool
    :param keywords: The information type keywords.
    :type keywords:
     list[~azure.mgmt.security.models.InformationProtectionKeyword]
    """

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'order': {'key': 'order', 'type': 'float'},
        'recommended_label_id': {'key': 'recommendedLabelId', 'type': 'str'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'custom': {'key': 'custom', 'type': 'bool'},
        'keywords': {'key': 'keywords', 'type': '[InformationProtectionKeyword]'},
    }

    def __init__(self, **kwargs):
        super(InformationType, self).__init__(**kwargs)
        self.display_name = kwargs.get('display_name', None)
        self.order = kwargs.get('order', None)
        self.recommended_label_id = kwargs.get('recommended_label_id', None)
        self.enabled = kwargs.get('enabled', None)
        self.custom = kwargs.get('custom', None)
        self.keywords = kwargs.get('keywords', None)
