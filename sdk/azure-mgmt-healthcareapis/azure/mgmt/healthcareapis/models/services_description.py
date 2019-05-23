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

from .resource import Resource


class ServicesDescription(Resource):
    """The description of the service.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :ivar kind: Required. The kind of the service. Valid values are: fhir.
     Default value: "fhir" .
    :vartype kind: str
    :param location: Required. The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    :param etag: An etag associated with the resource, used for optimistic
     concurrency when editing it.
    :type etag: str
    :param properties: The common properties of a service.
    :type properties: ~azure.mgmt.healthcareapis.models.ServicesProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True, 'pattern': r'^[a-z0-9][a-z0-9-]{1,21}[a-z0-9]$'},
        'type': {'readonly': True},
        'kind': {'required': True, 'constant': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ServicesProperties'},
    }

    def __init__(self, **kwargs):
        super(ServicesDescription, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
