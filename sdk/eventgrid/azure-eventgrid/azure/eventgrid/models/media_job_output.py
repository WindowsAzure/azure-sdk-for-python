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


class MediaJobOutput(Model):
    """The event data for a Job output.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: MediaJobOutputAsset

    All required parameters must be populated in order to send to Azure.

    :param error: Gets the Job output error.
    :type error: ~azure.eventgrid.models.MediaJobError
    :param label: Gets the Job output label.
    :type label: str
    :param progress: Required. Gets the Job output progress.
    :type progress: long
    :param state: Required. Gets the Job output state. Possible values
     include: 'Canceled', 'Canceling', 'Error', 'Finished', 'Processing',
     'Queued', 'Scheduled'
    :type state: str or ~azure.eventgrid.models.MediaJobState
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    """

    _validation = {
        'progress': {'required': True},
        'state': {'required': True},
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'MediaJobError'},
        'label': {'key': 'label', 'type': 'str'},
        'progress': {'key': 'progress', 'type': 'long'},
        'state': {'key': 'state', 'type': 'MediaJobState'},
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
    }

    _subtype_map = {
        'odatatype': {'#Microsoft.Media.JobOutputAsset': 'MediaJobOutputAsset'}
    }

    def __init__(self, **kwargs):
        super(MediaJobOutput, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)
        self.label = kwargs.get('label', None)
        self.progress = kwargs.get('progress', None)
        self.state = kwargs.get('state', None)
        self.odatatype = None
