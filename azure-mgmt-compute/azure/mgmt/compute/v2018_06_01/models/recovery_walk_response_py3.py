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


class RecoveryWalkResponse(Model):
    """Response after calling a manual recovery walk.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar walk_performed: Whether the recovery walk was performed
    :vartype walk_performed: bool
    :ivar next_platform_update_domain: The next update domain that needs to be
     walked. Null means walk spanning all update domains has been completed
    :vartype next_platform_update_domain: int
    """

    _validation = {
        'walk_performed': {'readonly': True},
        'next_platform_update_domain': {'readonly': True},
    }

    _attribute_map = {
        'walk_performed': {'key': 'walkPerformed', 'type': 'bool'},
        'next_platform_update_domain': {'key': 'nextPlatformUpdateDomain', 'type': 'int'},
    }

    def __init__(self, **kwargs) -> None:
        super(RecoveryWalkResponse, self).__init__(**kwargs)
        self.walk_performed = None
        self.next_platform_update_domain = None
