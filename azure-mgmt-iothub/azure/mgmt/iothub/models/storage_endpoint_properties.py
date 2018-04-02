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


class StorageEndpointProperties(Model):
    """The properties of the Azure Storage endpoint for file upload.

    All required parameters must be populated in order to send to Azure.

    :param sas_ttl_as_iso8601: The period of time for which the the SAS URI
     generated by IoT Hub for file upload is valid. See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-file-upload#file-upload-notification-configuration-options.
    :type sas_ttl_as_iso8601: timedelta
    :param connection_string: Required. The connection string for the Azure
     Storage account to which files are uploaded.
    :type connection_string: str
    :param container_name: Required. The name of the root container where you
     upload files. The container need not exist but should be creatable using
     the connectionString specified.
    :type container_name: str
    """

    _validation = {
        'connection_string': {'required': True},
        'container_name': {'required': True},
    }

    _attribute_map = {
        'sas_ttl_as_iso8601': {'key': 'sasTtlAsIso8601', 'type': 'duration'},
        'connection_string': {'key': 'connectionString', 'type': 'str'},
        'container_name': {'key': 'containerName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(StorageEndpointProperties, self).__init__(**kwargs)
        self.sas_ttl_as_iso8601 = kwargs.get('sas_ttl_as_iso8601', None)
        self.connection_string = kwargs.get('connection_string', None)
        self.container_name = kwargs.get('container_name', None)
