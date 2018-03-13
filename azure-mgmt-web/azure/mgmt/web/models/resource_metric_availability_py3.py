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


class ResourceMetricAvailability(Model):
    """Metrics availability and retention.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar time_grain: Time grain .
    :vartype time_grain: str
    :ivar retention: Retention period for the current time grain.
    :vartype retention: str
    """

    _validation = {
        'time_grain': {'readonly': True},
        'retention': {'readonly': True},
    }

    _attribute_map = {
        'time_grain': {'key': 'timeGrain', 'type': 'str'},
        'retention': {'key': 'retention', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ResourceMetricAvailability, self).__init__(**kwargs)
        self.time_grain = None
        self.retention = None
