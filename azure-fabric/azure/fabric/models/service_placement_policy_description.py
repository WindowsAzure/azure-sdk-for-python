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


class ServicePlacementPolicyDescription(Model):
    """The description of the service placement policy.

    :param type:
    :type type: str
    """

    _attribute_map = {
        'type': {'key': 'Type', 'type': 'str'},
    }

    def __init__(self, type=None):
        self.type = type
