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

from .job_input_clip_py3 import JobInputClip


class JobInputAsset(JobInputClip):
    """Represents an Asset for input into a Job.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param files: List of files. Required for JobInputHttp.
    :type files: list[str]
    :param label: A label that is assigned to a JobInputClip, that is used to
     satisfy a reference used in the Transform. For example, a Transform can be
     authored so as to take an image file with the label 'xyz' and apply it as
     an overlay onto the input video before it is encoded. When submitting a
     Job, exactly one of the JobInputs should be the image file, and it should
     have the label 'xyz'.
    :type label: str
    :param asset_name: Required. The name of the input Asset.
    :type asset_name: str
    """

    _validation = {
        'odatatype': {'required': True},
        'asset_name': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'files': {'key': 'files', 'type': '[str]'},
        'label': {'key': 'label', 'type': 'str'},
        'asset_name': {'key': 'assetName', 'type': 'str'},
    }

    def __init__(self, *, asset_name: str, files=None, label: str=None, **kwargs) -> None:
        super(JobInputAsset, self).__init__(files=files, label=label, **kwargs)
        self.asset_name = asset_name
        self.odatatype = '#Microsoft.Media.JobInputAsset'
