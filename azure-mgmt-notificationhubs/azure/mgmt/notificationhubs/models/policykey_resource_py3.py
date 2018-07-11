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


class PolicykeyResource(Model):
    """Namespace/NotificationHub Regenerate Keys.

    :param policy_key: Name of the key that has to be regenerated for the
     Namespace/Notification Hub Authorization Rule. The value can be Primary
     Key/Secondary Key.
    :type policy_key: str
    """

    _attribute_map = {
        'policy_key': {'key': 'policyKey', 'type': 'str'},
    }

    def __init__(self, *, policy_key: str=None, **kwargs) -> None:
        super(PolicykeyResource, self).__init__(**kwargs)
        self.policy_key = policy_key
