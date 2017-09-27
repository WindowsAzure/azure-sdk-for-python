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


class EdifactSchemaReference(Model):
    """The Edifact schema reference.

    :param message_id: The message id.
    :type message_id: str
    :param message_version: The message version.
    :type message_version: str
    :param message_release: The message release version.
    :type message_release: str
    :param sender_application_id: The sender application id.
    :type sender_application_id: str
    :param sender_application_qualifier: The sender application qualifier.
    :type sender_application_qualifier: str
    :param association_assigned_code: The association assigned code.
    :type association_assigned_code: str
    :param schema_name: The schema name.
    :type schema_name: str
    """

    _validation = {
        'message_id': {'required': True},
        'message_version': {'required': True},
        'message_release': {'required': True},
        'schema_name': {'required': True},
    }

    _attribute_map = {
        'message_id': {'key': 'messageId', 'type': 'str'},
        'message_version': {'key': 'messageVersion', 'type': 'str'},
        'message_release': {'key': 'messageRelease', 'type': 'str'},
        'sender_application_id': {'key': 'senderApplicationId', 'type': 'str'},
        'sender_application_qualifier': {'key': 'senderApplicationQualifier', 'type': 'str'},
        'association_assigned_code': {'key': 'associationAssignedCode', 'type': 'str'},
        'schema_name': {'key': 'schemaName', 'type': 'str'},
    }

    def __init__(self, message_id, message_version, message_release, schema_name, sender_application_id=None, sender_application_qualifier=None, association_assigned_code=None):
        self.message_id = message_id
        self.message_version = message_version
        self.message_release = message_release
        self.sender_application_id = sender_application_id
        self.sender_application_qualifier = sender_application_qualifier
        self.association_assigned_code = association_assigned_code
        self.schema_name = schema_name
