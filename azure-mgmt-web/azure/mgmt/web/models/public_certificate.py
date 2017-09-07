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

from .proxy_only_resource import ProxyOnlyResource


class PublicCertificate(ProxyOnlyResource):
    """Public certificate object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param blob: Public Certificate byte array
    :type blob: str
    :param public_certificate_location: Public Certificate Location. Possible
     values include: 'CurrentUserMy', 'LocalMachineMy', 'Unknown'
    :type public_certificate_location: str or
     :class:`PublicCertificateLocation
     <azure.mgmt.web.models.PublicCertificateLocation>`
    :ivar thumbprint: Certificate Thumbprint
    :vartype thumbprint: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'thumbprint': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'blob': {'key': 'properties.blob', 'type': 'str'},
        'public_certificate_location': {'key': 'properties.publicCertificateLocation', 'type': 'PublicCertificateLocation'},
        'thumbprint': {'key': 'properties.thumbprint', 'type': 'str'},
    }

    def __init__(self, kind=None, blob=None, public_certificate_location=None):
        super(PublicCertificate, self).__init__(kind=kind)
        self.blob = blob
        self.public_certificate_location = public_certificate_location
        self.thumbprint = None
