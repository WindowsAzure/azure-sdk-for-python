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


class CencDrmConfiguration(Model):
    """Class to specify drm configurations of CommonEncryptionCenc scheme in
    Streaming Policy.

    :param play_ready: PlayReady configurations
    :type play_ready:
     ~azure.mgmt.media.models.StreamingPolicyPlayReadyConfiguration
    :param widevine: Widevine configurations
    :type widevine:
     ~azure.mgmt.media.models.StreamingPolicyWidevineConfiguration
    """

    _attribute_map = {
        'play_ready': {'key': 'playReady', 'type': 'StreamingPolicyPlayReadyConfiguration'},
        'widevine': {'key': 'widevine', 'type': 'StreamingPolicyWidevineConfiguration'},
    }

    def __init__(self, *, play_ready=None, widevine=None, **kwargs) -> None:
        super(CencDrmConfiguration, self).__init__(**kwargs)
        self.play_ready = play_ready
        self.widevine = widevine
