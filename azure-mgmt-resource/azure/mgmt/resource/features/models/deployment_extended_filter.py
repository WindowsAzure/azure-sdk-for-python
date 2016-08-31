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


class DeploymentExtendedFilter(Model):
    """Deployment filter.

    :param provisioning_state: Gets or sets the provisioning state.
    :type provisioning_state: str
    """ 

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
    }

    def __init__(self, provisioning_state=None):
        self.provisioning_state = provisioning_state
