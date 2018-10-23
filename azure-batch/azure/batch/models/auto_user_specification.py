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


class AutoUserSpecification(Model):
    """Specifies the parameters for the auto user that runs a task on the Batch
    service.

    :param scope: The scope for the auto user. The default value is task.
     Possible values include: 'task', 'pool'
    :type scope: str or ~azure.batch.models.AutoUserScope
    :param elevation_level: The elevation level of the auto user. The default
     value is nonAdmin. Possible values include: 'nonAdmin', 'admin'
    :type elevation_level: str or ~azure.batch.models.ElevationLevel
    """

    _attribute_map = {
        'scope': {'key': 'scope', 'type': 'AutoUserScope'},
        'elevation_level': {'key': 'elevationLevel', 'type': 'ElevationLevel'},
    }

    def __init__(self, **kwargs):
        super(AutoUserSpecification, self).__init__(**kwargs)
        self.scope = kwargs.get('scope', None)
        self.elevation_level = kwargs.get('elevation_level', None)
