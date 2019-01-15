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


class ContentKeyPolicyTokenClaim(Model):
    """Represents a token claim.

    :param claim_type: Token claim type.
    :type claim_type: str
    :param claim_value: Token claim value.
    :type claim_value: str
    """

    _attribute_map = {
        'claim_type': {'key': 'claimType', 'type': 'str'},
        'claim_value': {'key': 'claimValue', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ContentKeyPolicyTokenClaim, self).__init__(**kwargs)
        self.claim_type = kwargs.get('claim_type', None)
        self.claim_value = kwargs.get('claim_value', None)
