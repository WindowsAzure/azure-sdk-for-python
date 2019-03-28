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


class LogStorageSettings(Model):
    """Log storage settings.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param linked_service_name: Required. Log storage linked service
     reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param path: The path to storage for storing detailed logs of activity
     execution. Type: string (or Expression with resultType string).
    :type path: object
    """

    _validation = {
        'linked_service_name': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'path': {'key': 'path', 'type': 'object'},
    }

    def __init__(self, *, linked_service_name, additional_properties=None, path=None, **kwargs) -> None:
        super(LogStorageSettings, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.linked_service_name = linked_service_name
        self.path = path
