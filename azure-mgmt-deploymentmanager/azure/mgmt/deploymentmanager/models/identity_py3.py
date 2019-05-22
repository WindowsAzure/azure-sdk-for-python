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


class Identity(Model):
    """Identity for the resource.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. The identity type.
    :type type: str
    :param identity_ids: Required. The list of identities.
    :type identity_ids: list[str]
    """

    _validation = {
        'type': {'required': True},
        'identity_ids': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'identity_ids': {'key': 'identityIds', 'type': '[str]'},
    }

    def __init__(self, *, type: str, identity_ids, **kwargs) -> None:
        super(Identity, self).__init__(**kwargs)
        self.type = type
        self.identity_ids = identity_ids
