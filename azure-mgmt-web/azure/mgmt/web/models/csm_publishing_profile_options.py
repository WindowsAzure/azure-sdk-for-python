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


class CsmPublishingProfileOptions(Model):
    """Publishing options for requested profile.

    :param format: Name of the format. Valid values are:
     FileZilla3
     WebDeploy -- default
     Ftp. Possible values include: 'FileZilla3', 'WebDeploy', 'Ftp'
    :type format: str or ~azure.mgmt.web.models.PublishingProfileFormat
    """

    _attribute_map = {
        'format': {'key': 'format', 'type': 'str'},
    }

    def __init__(self, format=None):
        super(CsmPublishingProfileOptions, self).__init__()
        self.format = format
