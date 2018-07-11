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


class InstantItemRecoveryTarget(Model):
    """Target details for file / folder restore.

    :param client_scripts: List of client scripts.
    :type client_scripts:
     list[~azure.mgmt.recoveryservicesbackup.models.ClientScriptForConnect]
    """

    _attribute_map = {
        'client_scripts': {'key': 'clientScripts', 'type': '[ClientScriptForConnect]'},
    }

    def __init__(self, *, client_scripts=None, **kwargs) -> None:
        super(InstantItemRecoveryTarget, self).__init__(**kwargs)
        self.client_scripts = client_scripts
