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


class RegistrationDelegationSettingsProperties(Model):
    """User registration delegation settings properties.

    :param enabled: Enable or disable delegation for user registration.
    :type enabled: bool
    """

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
    }

    def __init__(self, *, enabled: bool=None, **kwargs) -> None:
        super(RegistrationDelegationSettingsProperties, self).__init__(**kwargs)
        self.enabled = enabled
