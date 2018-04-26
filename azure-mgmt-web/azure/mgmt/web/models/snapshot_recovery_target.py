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


class SnapshotRecoveryTarget(Model):
    """Specifies the web app that snapshot contents will be written to.

    :param location: Geographical location of the target web app, e.g.
     SouthEastAsia, SouthCentralUS
    :type location: str
    :param id: ARM resource ID of the target app.
     /subscriptions/{subId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}
     for production slots and
     /subscriptions/{subId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{siteName}/slots/{slotName}
     for other slots.
    :type id: str
    """

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SnapshotRecoveryTarget, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.id = kwargs.get('id', None)
