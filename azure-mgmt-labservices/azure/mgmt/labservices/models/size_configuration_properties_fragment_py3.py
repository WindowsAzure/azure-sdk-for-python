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


class SizeConfigurationPropertiesFragment(Model):
    """Represents the size configuration under the lab account.

    :param environment_sizes: Represents a list of size categories supported
     by this Lab Account (Small, Medium, Large)
    :type environment_sizes:
     list[~azure.mgmt.labservices.models.EnvironmentSizeFragment]
    """

    _attribute_map = {
        'environment_sizes': {'key': 'environmentSizes', 'type': '[EnvironmentSizeFragment]'},
    }

    def __init__(self, *, environment_sizes=None, **kwargs) -> None:
        super(SizeConfigurationPropertiesFragment, self).__init__(**kwargs)
        self.environment_sizes = environment_sizes
