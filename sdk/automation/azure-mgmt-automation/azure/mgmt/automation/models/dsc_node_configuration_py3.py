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


class DscNodeConfiguration(ProxyResource):
    """Definition of the dsc node configuration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param last_modified_time: Gets or sets the last modified time.
    :type last_modified_time: datetime
    :param creation_time: Gets or sets creation time.
    :type creation_time: datetime
    :param configuration: Gets or sets the configuration of the node.
    :type configuration:
     ~azure.mgmt.automation.models.DscConfigurationAssociationProperty
    :param source: Source of node configuration.
    :type source: str
    :param node_count: Number of nodes with this node configuration assigned
    :type node_count: long
    :param increment_node_configuration_build: If a new build version of
     NodeConfiguration is required.
    :type increment_node_configuration_build: bool
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
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'configuration': {'key': 'properties.configuration', 'type': 'DscConfigurationAssociationProperty'},
        'source': {'key': 'properties.source', 'type': 'str'},
        'node_count': {'key': 'properties.nodeCount', 'type': 'long'},
        'increment_node_configuration_build': {'key': 'properties.incrementNodeConfigurationBuild', 'type': 'bool'},
    }

    def __init__(self, *, last_modified_time=None, creation_time=None, configuration=None, source: str=None, node_count: int=None, increment_node_configuration_build: bool=None, **kwargs) -> None:
        super(DscNodeConfiguration, self).__init__(**kwargs)
        self.last_modified_time = last_modified_time
        self.creation_time = creation_time
        self.configuration = configuration
        self.source = source
        self.node_count = node_count
        self.increment_node_configuration_build = increment_node_configuration_build
