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


class EnterpriseChannelProperties(Model):
    """The parameters to provide for the Enterprise Channel.

    All required parameters must be populated in order to send to Azure.

    :param state: The current state of the Enterprise Channel. Possible values
     include: 'Creating', 'CreateFailed', 'Started', 'Starting', 'StartFailed',
     'Stopped', 'Stopping', 'StopFailed', 'Deleting', 'DeleteFailed'
    :type state: str or ~azure.mgmt.botservice.models.ChannelState
    :param nodes: Required. The nodes associated with the Enterprise Channel.
    :type nodes: list[~azure.mgmt.botservice.models.EnterpriseChannelNode]
    """

    _validation = {
        'nodes': {'required': True},
    }

    _attribute_map = {
        'state': {'key': 'state', 'type': 'str'},
        'nodes': {'key': 'nodes', 'type': '[EnterpriseChannelNode]'},
    }

    def __init__(self, *, nodes, state=None, **kwargs) -> None:
        super(EnterpriseChannelProperties, self).__init__(**kwargs)
        self.state = state
        self.nodes = nodes
