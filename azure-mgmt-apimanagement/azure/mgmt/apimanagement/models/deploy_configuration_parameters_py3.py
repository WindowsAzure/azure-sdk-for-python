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


class DeployConfigurationParameters(Model):
    """Parameters supplied to the Deploy Configuration operation.

    All required parameters must be populated in order to send to Azure.

    :param branch: Required. The name of the Git branch from which the
     configuration is to be deployed to the configuration database.
    :type branch: str
    :param force: The value enforcing deleting subscriptions to products that
     are deleted in this update.
    :type force: bool
    """

    _validation = {
        'branch': {'required': True},
    }

    _attribute_map = {
        'branch': {'key': 'branch', 'type': 'str'},
        'force': {'key': 'force', 'type': 'bool'},
    }

    def __init__(self, *, branch: str, force: bool=None, **kwargs) -> None:
        super(DeployConfigurationParameters, self).__init__(**kwargs)
        self.branch = branch
        self.force = force
