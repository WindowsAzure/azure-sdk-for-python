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


class ContainerRegistryEventRequest(Model):
    """The request that generated the event.

    :param id: The ID of the request that initiated the event.
    :type id: str
    :param addr: The IP or hostname and possibly port of the client connection
     that initiated the event. This is the RemoteAddr from the standard http
     request.
    :type addr: str
    :param host: The externally accessible hostname of the registry instance,
     as specified by the http host header on incoming requests.
    :type host: str
    :param method: The request method that generated the event.
    :type method: str
    :param useragent: The user agent header of the request.
    :type useragent: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'addr': {'key': 'addr', 'type': 'str'},
        'host': {'key': 'host', 'type': 'str'},
        'method': {'key': 'method', 'type': 'str'},
        'useragent': {'key': 'useragent', 'type': 'str'},
    }

    def __init__(self, id=None, addr=None, host=None, method=None, useragent=None):
        super(ContainerRegistryEventRequest, self).__init__()
        self.id = id
        self.addr = addr
        self.host = host
        self.method = method
        self.useragent = useragent
