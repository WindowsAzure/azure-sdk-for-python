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


class CertificateIssuerUpdateParameters(Model):
    """The certificate issuer update parameters.

    :param provider: The issuer provider.
    :type provider: str
    :param credentials: The credentials to be used for the issuer.
    :type credentials: ~azure.keyvault.v2016_10_01.models.IssuerCredentials
    :param organization_details: Details of the organization as provided to
     the issuer.
    :type organization_details:
     ~azure.keyvault.v2016_10_01.models.OrganizationDetails
    :param attributes: Attributes of the issuer object.
    :type attributes: ~azure.keyvault.v2016_10_01.models.IssuerAttributes
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'credentials': {'key': 'credentials', 'type': 'IssuerCredentials'},
        'organization_details': {'key': 'org_details', 'type': 'OrganizationDetails'},
        'attributes': {'key': 'attributes', 'type': 'IssuerAttributes'},
    }

    def __init__(self, **kwargs):
        super(CertificateIssuerUpdateParameters, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.credentials = kwargs.get('credentials', None)
        self.organization_details = kwargs.get('organization_details', None)
        self.attributes = kwargs.get('attributes', None)
