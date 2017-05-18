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


class UpdateServiceGroupDescription(Model):
    """The description of the update service group.

    :param flags:
    :type flags: int
    :param service_kind: Polymorphic Discriminator
    :type service_kind: str
    """

    _validation = {
        'service_kind': {'required': True},
    }

    _attribute_map = {
        'flags': {'key': 'Flags', 'type': 'int'},
        'service_kind': {'key': 'ServiceKind', 'type': 'str'},
    }

    _subtype_map = {
        'service_kind': {'Stateless': 'StatelessUpdateServiceGroupDescription', 'Stateful': 'StatefulUpdateServiceGroupDescription'}
    }

    def __init__(self, flags=None):
        self.flags = flags
        self.service_kind = None
