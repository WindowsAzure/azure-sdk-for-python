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


class Application(ProxyResource):
    """The HDInsight cluster application.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource.
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param etag: The ETag for the application
    :type etag: str
    :param tags: The tags for the application.
    :type tags: dict[str, str]
    :param properties: The properties of the application.
    :type properties: ~azure.mgmt.hdinsight.models.ApplicationGetProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'ApplicationGetProperties'},
    }

    def __init__(self, etag=None, tags=None, properties=None):
        super(Application, self).__init__()
        self.etag = etag
        self.tags = tags
        self.properties = properties
