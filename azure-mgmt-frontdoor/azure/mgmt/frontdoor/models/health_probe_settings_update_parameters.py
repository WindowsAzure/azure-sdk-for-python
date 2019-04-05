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


class HealthProbeSettingsUpdateParameters(Model):
    """L7 health probe settings for a backend pool.

    :param path: The path to use for the health probe. Default is /
    :type path: str
    :param protocol: Protocol scheme to use for this probe. Possible values
     include: 'Http', 'Https'
    :type protocol: str or ~azure.mgmt.frontdoor.models.FrontDoorProtocol
    :param interval_in_seconds: The number of seconds between health probes.
    :type interval_in_seconds: int
    """

    _attribute_map = {
        'path': {'key': 'path', 'type': 'str'},
        'protocol': {'key': 'protocol', 'type': 'str'},
        'interval_in_seconds': {'key': 'intervalInSeconds', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(HealthProbeSettingsUpdateParameters, self).__init__(**kwargs)
        self.path = kwargs.get('path', None)
        self.protocol = kwargs.get('protocol', None)
        self.interval_in_seconds = kwargs.get('interval_in_seconds', None)
