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


class DscNode(ProxyResource):
    """Definition of a DscNode.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param last_seen: Gets or sets the last seen time of the node.
    :type last_seen: datetime
    :param registration_time: Gets or sets the registration time of the node.
    :type registration_time: datetime
    :param ip: Gets or sets the ip of the node.
    :type ip: str
    :param account_id: Gets or sets the account id of the node.
    :type account_id: str
    :param dsc_node_name: Gets or sets the name of the dsc nodeconfiguration.
    :type dsc_node_name: str
    :param status: Gets or sets the status of the node.
    :type status: str
    :param node_id: Gets or sets the node id.
    :type node_id: str
    :param etag: Gets or sets the etag of the resource.
    :type etag: str
    :param total_count: Gets the total number of records matching filter
     criteria.
    :type total_count: int
    :param extension_handler: Gets or sets the list of extensionHandler
     properties for a Node.
    :type extension_handler:
     list[~azure.mgmt.automation.models.DscNodeExtensionHandlerAssociationProperty]
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
        'last_seen': {'key': 'properties.lastSeen', 'type': 'iso-8601'},
        'registration_time': {'key': 'properties.registrationTime', 'type': 'iso-8601'},
        'ip': {'key': 'properties.ip', 'type': 'str'},
        'account_id': {'key': 'properties.accountId', 'type': 'str'},
        'dsc_node_name': {'key': 'properties.nodeConfiguration.name', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'node_id': {'key': 'properties.nodeId', 'type': 'str'},
        'etag': {'key': 'properties.etag', 'type': 'str'},
        'total_count': {'key': 'properties.totalCount', 'type': 'int'},
        'extension_handler': {'key': 'properties.extensionHandler', 'type': '[DscNodeExtensionHandlerAssociationProperty]'},
    }

    def __init__(self, **kwargs):
        super(DscNode, self).__init__(**kwargs)
        self.last_seen = kwargs.get('last_seen', None)
        self.registration_time = kwargs.get('registration_time', None)
        self.ip = kwargs.get('ip', None)
        self.account_id = kwargs.get('account_id', None)
        self.dsc_node_name = kwargs.get('dsc_node_name', None)
        self.status = kwargs.get('status', None)
        self.node_id = kwargs.get('node_id', None)
        self.etag = kwargs.get('etag', None)
        self.total_count = kwargs.get('total_count', None)
        self.extension_handler = kwargs.get('extension_handler', None)
