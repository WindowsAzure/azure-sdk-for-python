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


class EntityExpandParameters(Model):
    """The parameters required to execute an expand operation on the given entity.

    :param end_time: The end date filter, so the only expansion results
     returned are before this date.
    :type end_time: datetime
    :param expansion_id: The Id of the expansion to perform.
    :type expansion_id: str
    :param start_time: The start date filter, so the only expansion results
     returned are after this date.
    :type start_time: datetime
    """

    _attribute_map = {
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'expansion_id': {'key': 'expansionId', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(EntityExpandParameters, self).__init__(**kwargs)
        self.end_time = kwargs.get('end_time', None)
        self.expansion_id = kwargs.get('expansion_id', None)
        self.start_time = kwargs.get('start_time', None)
