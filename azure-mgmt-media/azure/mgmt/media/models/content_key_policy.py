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

from .proxy_resource import ProxyResource


class ContentKeyPolicy(ProxyResource):
    """A Content Key Policy resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :ivar policy_id: The legacy Policy ID.
    :vartype policy_id: str
    :ivar created: The creation date of the Policy
    :vartype created: datetime
    :ivar last_modified: The last modified date of the Policy
    :vartype last_modified: datetime
    :param description: A description for the Policy.
    :type description: str
    :param options: Required. The Key Policy options.
    :type options: list[~azure.mgmt.media.models.ContentKeyPolicyOption]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'policy_id': {'readonly': True},
        'created': {'readonly': True},
        'last_modified': {'readonly': True},
        'options': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'policy_id': {'key': 'properties.policyId', 'type': 'str'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'last_modified': {'key': 'properties.lastModified', 'type': 'iso-8601'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'options': {'key': 'properties.options', 'type': '[ContentKeyPolicyOption]'},
    }

    def __init__(self, **kwargs):
        super(ContentKeyPolicy, self).__init__(**kwargs)
        self.policy_id = None
        self.created = None
        self.last_modified = None
        self.description = kwargs.get('description', None)
        self.options = kwargs.get('options', None)
