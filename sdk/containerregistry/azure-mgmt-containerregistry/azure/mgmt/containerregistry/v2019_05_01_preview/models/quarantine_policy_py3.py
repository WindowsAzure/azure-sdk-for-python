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


class QuarantinePolicy(Model):
    """An object that represents quarantine policy for a container registry.

    :param status: The value that indicates whether the policy is enabled or
     not. Possible values include: 'enabled', 'disabled'
    :type status: str or
     ~azure.mgmt.containerregistry.v2019_05_01_preview.models.PolicyStatus
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(self, *, status=None, **kwargs) -> None:
        super(QuarantinePolicy, self).__init__(**kwargs)
        self.status = status
