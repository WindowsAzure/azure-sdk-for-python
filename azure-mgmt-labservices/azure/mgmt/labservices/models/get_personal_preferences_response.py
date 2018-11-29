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


class GetPersonalPreferencesResponse(Model):
    """Represents the PersonalPreferences for the user.

    :param id: Id to be used by the cache orchestrator
    :type id: str
    :param favorite_lab_resource_ids: Array of favorite lab resource ids
    :type favorite_lab_resource_ids: list[str]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'favorite_lab_resource_ids': {'key': 'favoriteLabResourceIds', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(GetPersonalPreferencesResponse, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.favorite_lab_resource_ids = kwargs.get('favorite_lab_resource_ids', None)
