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


class AgentRegistrationRegenerateKeyParameter(Model):
    """The parameters supplied to the regenerate keys operation.

    :param key_name: Gets or sets the agent registration key name - Primary or
     Secondary. Possible values include: 'Primary', 'Secondary'
    :type key_name: str or
     ~azure.mgmt.automation.models.AgentRegistrationKeyName
    :param name: Gets or sets the name of the resource.
    :type name: str
    :param location: Gets or sets the location of the resource.
    :type location: str
    :param tags: Gets or sets the tags attached to the resource.
    :type tags: dict[str, str]
    """

    _validation = {
        'key_name': {'required': True},
    }

    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, key_name, name=None, location=None, tags=None):
        super(AgentRegistrationRegenerateKeyParameter, self).__init__()
        self.key_name = key_name
        self.name = name
        self.location = location
        self.tags = tags
