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


class StreamingPolicyContentKeys(Model):
    """Class to specify properties of all content keys in Streaming Policy.

    :param default_key: Default content key for an encryption scheme
    :type default_key: ~azure.mgmt.media.models.DefaultKey
    :param key_to_track_mappings: Representing tracks needs separate content
     key
    :type key_to_track_mappings:
     list[~azure.mgmt.media.models.StreamingPolicyContentKey]
    """

    _attribute_map = {
        'default_key': {'key': 'defaultKey', 'type': 'DefaultKey'},
        'key_to_track_mappings': {'key': 'keyToTrackMappings', 'type': '[StreamingPolicyContentKey]'},
    }

    def __init__(self, *, default_key=None, key_to_track_mappings=None, **kwargs) -> None:
        super(StreamingPolicyContentKeys, self).__init__(**kwargs)
        self.default_key = default_key
        self.key_to_track_mappings = key_to_track_mappings
