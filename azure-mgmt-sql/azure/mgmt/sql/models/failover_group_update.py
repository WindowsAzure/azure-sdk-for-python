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


class FailoverGroupUpdate(Model):
    """A failover group update request.

    :param read_write_endpoint: Read-write endpoint of the failover group
     instance.
    :type read_write_endpoint: :class:`FailoverGroupReadWriteEndpoint
     <azure.mgmt.sql.models.FailoverGroupReadWriteEndpoint>`
    :param read_only_endpoint: Read-only endpoint of the failover group
     instance.
    :type read_only_endpoint: :class:`FailoverGroupReadOnlyEndpoint
     <azure.mgmt.sql.models.FailoverGroupReadOnlyEndpoint>`
    :param databases: List of databases in the failover group.
    :type databases: list of str
    :param tags: Resource tags.
    :type tags: dict
    """

    _attribute_map = {
        'read_write_endpoint': {'key': 'properties.readWriteEndpoint', 'type': 'FailoverGroupReadWriteEndpoint'},
        'read_only_endpoint': {'key': 'properties.readOnlyEndpoint', 'type': 'FailoverGroupReadOnlyEndpoint'},
        'databases': {'key': 'properties.databases', 'type': '[str]'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, read_write_endpoint=None, read_only_endpoint=None, databases=None, tags=None):
        self.read_write_endpoint = read_write_endpoint
        self.read_only_endpoint = read_only_endpoint
        self.databases = databases
        self.tags = tags
