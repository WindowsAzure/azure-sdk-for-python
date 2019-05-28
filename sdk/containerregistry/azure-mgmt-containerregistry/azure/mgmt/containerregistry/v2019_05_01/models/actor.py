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


class Actor(Model):
    """The agent that initiated the event. For most situations, this could be from
    the authorization context of the request.

    :param name: The subject or username associated with the request context
     that generated the event.
    :type name: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Actor, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
