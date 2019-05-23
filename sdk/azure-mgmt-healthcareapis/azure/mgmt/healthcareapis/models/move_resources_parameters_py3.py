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


class MoveResourcesParameters(Model):
    """Input values.

    All required parameters must be populated in order to send to Azure.

    :param target_subscription_id: Required. The target subscription to move
     resources to.
    :type target_subscription_id: str
    :param target_resource_group_name: Required. The target resource group to
     move resources to.
    :type target_resource_group_name: str
    :param resource_ids_to_move: Required. The list of resources to move.
    :type resource_ids_to_move: list[str]
    """

    _validation = {
        'target_subscription_id': {'required': True},
        'target_resource_group_name': {'required': True},
        'resource_ids_to_move': {'required': True, 'max_items': 250, 'min_items': 1},
    }

    _attribute_map = {
        'target_subscription_id': {'key': 'targetSubscriptionId', 'type': 'str'},
        'target_resource_group_name': {'key': 'targetResourceGroupName', 'type': 'str'},
        'resource_ids_to_move': {'key': 'resourceIdsToMove', 'type': '[str]'},
    }

    def __init__(self, *, target_subscription_id: str, target_resource_group_name: str, resource_ids_to_move, **kwargs) -> None:
        super(MoveResourcesParameters, self).__init__(**kwargs)
        self.target_subscription_id = target_subscription_id
        self.target_resource_group_name = target_resource_group_name
        self.resource_ids_to_move = resource_ids_to_move
