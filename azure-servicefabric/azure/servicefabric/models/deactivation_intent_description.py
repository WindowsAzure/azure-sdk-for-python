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


class DeactivationIntentDescription(Model):
    """Describes the intent or reason for deactivating the node.

    :param deactivation_intent: Describes the intent or reason for
     deactivating the node. The possible values are following.
     - Pause - Indicates that the node should be paused. The value is 1.
     - Restart - Indicates that the intent is for the node to be restarted
     after a short period of time. The value is 2.
     - RemoveData - Indicates the intent is for the node to remove data. The
     value is 3.
     . Possible values include: 'Pause', 'Restart', 'RemoveData'
    :type deactivation_intent: str or ~azure.servicefabric.models.enum
    """

    _attribute_map = {
        'deactivation_intent': {'key': 'DeactivationIntent', 'type': 'str'},
    }

    def __init__(self, deactivation_intent=None):
        super(DeactivationIntentDescription, self).__init__()
        self.deactivation_intent = deactivation_intent
