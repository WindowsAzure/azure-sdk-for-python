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

from .proxy_resource_py3 import ProxyResource


class Transform(ProxyResource):
    """A Transform encapsulates the rules or instructions for generating desired
    outputs from input media, such as by transcoding or by extracting insights.
    After the Transform is created, it can be applied to input media by
    creating Jobs.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :ivar created: The UTC date and time when the Transform was created, in
     'YYYY-MM-DDThh:mm:ssZ' format.
    :vartype created: datetime
    :param description: An optional verbose description of the Transform.
    :type description: str
    :ivar last_modified: The UTC date and time when the Transform was last
     updated, in 'YYYY-MM-DDThh:mm:ssZ' format.
    :vartype last_modified: datetime
    :param outputs: Required. An array of one or more TransformOutputs that
     the Transform should generate.
    :type outputs: list[~azure.mgmt.media.models.TransformOutput]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created': {'readonly': True},
        'last_modified': {'readonly': True},
        'outputs': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'last_modified': {'key': 'properties.lastModified', 'type': 'iso-8601'},
        'outputs': {'key': 'properties.outputs', 'type': '[TransformOutput]'},
    }

    def __init__(self, *, outputs, description: str=None, **kwargs) -> None:
        super(Transform, self).__init__(**kwargs)
        self.created = None
        self.description = description
        self.last_modified = None
        self.outputs = outputs
