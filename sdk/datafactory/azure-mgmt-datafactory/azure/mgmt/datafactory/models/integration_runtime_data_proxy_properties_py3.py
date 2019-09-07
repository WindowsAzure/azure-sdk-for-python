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


class IntegrationRuntimeDataProxyProperties(Model):
    """Data proxy properties for a managed dedicated integration runtime.

    :param connect_via: The self-hosted integration runtime reference.
    :type connect_via: ~azure.mgmt.datafactory.models.EntityReference
    :param staging_linked_service: The staging linked service reference.
    :type staging_linked_service:
     ~azure.mgmt.datafactory.models.EntityReference
    :param path: The path to contain the staged data in the Blob storage.
    :type path: str
    """

    _attribute_map = {
        'connect_via': {'key': 'connectVia', 'type': 'EntityReference'},
        'staging_linked_service': {'key': 'stagingLinkedService', 'type': 'EntityReference'},
        'path': {'key': 'path', 'type': 'str'},
    }

    def __init__(self, *, connect_via=None, staging_linked_service=None, path: str=None, **kwargs) -> None:
        super(IntegrationRuntimeDataProxyProperties, self).__init__(**kwargs)
        self.connect_via = connect_via
        self.staging_linked_service = staging_linked_service
        self.path = path
