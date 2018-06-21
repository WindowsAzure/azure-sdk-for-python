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

from .content_key_policy_restriction_py3 import ContentKeyPolicyRestriction


class ContentKeyPolicyTokenRestriction(ContentKeyPolicyRestriction):
    """Represents a token restriction. Provided token must match these
    requirements for successful license or key delivery.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param issuer: Required. The token issuer.
    :type issuer: str
    :param audience: Required. The audience for the token.
    :type audience: str
    :param primary_verification_key: Required. The primary verification key.
    :type primary_verification_key:
     ~azure.mgmt.media.models.ContentKeyPolicyRestrictionTokenKey
    :param alternate_verification_keys: A list of alternative verification
     keys.
    :type alternate_verification_keys:
     list[~azure.mgmt.media.models.ContentKeyPolicyRestrictionTokenKey]
    :param required_claims: A list of required token claims.
    :type required_claims:
     list[~azure.mgmt.media.models.ContentKeyPolicyTokenClaim]
    :param restriction_token_type: Required. The type of token. Possible
     values include: 'Unknown', 'Swt', 'Jwt'
    :type restriction_token_type: str or
     ~azure.mgmt.media.models.ContentKeyPolicyRestrictionTokenType
    :param open_id_connect_discovery_document: The OpenID connect discovery
     document.
    :type open_id_connect_discovery_document: str
    """

    _validation = {
        'odatatype': {'required': True},
        'issuer': {'required': True},
        'audience': {'required': True},
        'primary_verification_key': {'required': True},
        'restriction_token_type': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'issuer': {'key': 'issuer', 'type': 'str'},
        'audience': {'key': 'audience', 'type': 'str'},
        'primary_verification_key': {'key': 'primaryVerificationKey', 'type': 'ContentKeyPolicyRestrictionTokenKey'},
        'alternate_verification_keys': {'key': 'alternateVerificationKeys', 'type': '[ContentKeyPolicyRestrictionTokenKey]'},
        'required_claims': {'key': 'requiredClaims', 'type': '[ContentKeyPolicyTokenClaim]'},
        'restriction_token_type': {'key': 'restrictionTokenType', 'type': 'ContentKeyPolicyRestrictionTokenType'},
        'open_id_connect_discovery_document': {'key': 'openIdConnectDiscoveryDocument', 'type': 'str'},
    }

    def __init__(self, *, issuer: str, audience: str, primary_verification_key, restriction_token_type, alternate_verification_keys=None, required_claims=None, open_id_connect_discovery_document: str=None, **kwargs) -> None:
        super(ContentKeyPolicyTokenRestriction, self).__init__(**kwargs)
        self.issuer = issuer
        self.audience = audience
        self.primary_verification_key = primary_verification_key
        self.alternate_verification_keys = alternate_verification_keys
        self.required_claims = required_claims
        self.restriction_token_type = restriction_token_type
        self.open_id_connect_discovery_document = open_id_connect_discovery_document
        self.odatatype = '#Microsoft.Media.ContentKeyPolicyTokenRestriction'
