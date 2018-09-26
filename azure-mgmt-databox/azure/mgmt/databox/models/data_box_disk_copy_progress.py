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


class DataBoxDiskCopyProgress(Model):
    """DataBox Disk Copy Progress.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar serial_number: The serial number of the disk
    :vartype serial_number: str
    :ivar bytes_copied: Bytes copied during the copy of disk.
    :vartype bytes_copied: long
    :ivar percent_complete: Indicates the percentage completed for the copy of
     the disk.
    :vartype percent_complete: int
    :ivar status: The Status of the copy. Possible values include:
     'NotStarted', 'InProgress', 'Completed', 'CompletedWithErrors', 'Failed',
     'NotReturned'
    :vartype status: str or ~azure.mgmt.databox.models.CopyStatus
    """

    _validation = {
        'serial_number': {'readonly': True},
        'bytes_copied': {'readonly': True},
        'percent_complete': {'readonly': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'serial_number': {'key': 'serialNumber', 'type': 'str'},
        'bytes_copied': {'key': 'bytesCopied', 'type': 'long'},
        'percent_complete': {'key': 'percentComplete', 'type': 'int'},
        'status': {'key': 'status', 'type': 'CopyStatus'},
    }

    def __init__(self, **kwargs):
        super(DataBoxDiskCopyProgress, self).__init__(**kwargs)
        self.serial_number = None
        self.bytes_copied = None
        self.percent_complete = None
        self.status = None
