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


class TagProperty(Model):
    """A tag of the LegalHold of a blob container.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar tag: The tag value.
    :vartype tag: str
    :ivar timestamp: Returns the date and time the tag was added.
    :vartype timestamp: datetime
    :ivar object_identifier: Returns the Object ID of the user who added the
     tag.
    :vartype object_identifier: str
    :ivar tenant_id: Returns the Tenant ID that issued the token for the user
     who added the tag.
    :vartype tenant_id: str
    :ivar upn: Returns the User Principal Name of the user who added the tag.
    :vartype upn: str
    """

    _validation = {
        'tag': {'readonly': True},
        'timestamp': {'readonly': True},
        'object_identifier': {'readonly': True},
        'tenant_id': {'readonly': True},
        'upn': {'readonly': True},
    }

    _attribute_map = {
        'tag': {'key': 'tag', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'object_identifier': {'key': 'objectIdentifier', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'upn': {'key': 'upn', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(TagProperty, self).__init__(**kwargs)
        self.tag = None
        self.timestamp = None
        self.object_identifier = None
        self.tenant_id = None
        self.upn = None
