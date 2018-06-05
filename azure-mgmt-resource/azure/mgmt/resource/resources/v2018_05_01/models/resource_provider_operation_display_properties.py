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


class ResourceProviderOperationDisplayProperties(Model):
    """Resource provider operation's display properties.

    :param publisher: Operation description.
    :type publisher: str
    :param provider: Operation provider.
    :type provider: str
    :param resource: Operation resource.
    :type resource: str
    :param operation: Operation.
    :type operation: str
    :param description: Operation description.
    :type description: str
    """

    _attribute_map = {
        'publisher': {'key': 'publisher', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ResourceProviderOperationDisplayProperties, self).__init__(**kwargs)
        self.publisher = kwargs.get('publisher', None)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)
