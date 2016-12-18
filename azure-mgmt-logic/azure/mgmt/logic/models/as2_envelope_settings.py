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


class AS2EnvelopeSettings(Model):
    """AS2EnvelopeSettings.

    :param message_content_type: The message content type.
    :type message_content_type: str
    :param transmit_file_name_in_mime_header: The value indicating whether to
     transmit file name in mime header.
    :type transmit_file_name_in_mime_header: bool
    :param file_name_template: The template for file name.
    :type file_name_template: str
    :param suspend_message_on_file_name_generation_error: The value indicating
     whether to suspend message on file name generation error.
    :type suspend_message_on_file_name_generation_error: bool
    :param autogenerate_file_name: The value indicating whether to auto
     generate file name.
    :type autogenerate_file_name: bool
    """

    _attribute_map = {
        'message_content_type': {'key': 'messageContentType', 'type': 'str'},
        'transmit_file_name_in_mime_header': {'key': 'transmitFileNameInMimeHeader', 'type': 'bool'},
        'file_name_template': {'key': 'fileNameTemplate', 'type': 'str'},
        'suspend_message_on_file_name_generation_error': {'key': 'SuspendMessageOnFileNameGenerationError', 'type': 'bool'},
        'autogenerate_file_name': {'key': 'AutogenerateFileName', 'type': 'bool'},
    }

    def __init__(self, message_content_type=None, transmit_file_name_in_mime_header=None, file_name_template=None, suspend_message_on_file_name_generation_error=None, autogenerate_file_name=None):
        self.message_content_type = message_content_type
        self.transmit_file_name_in_mime_header = transmit_file_name_in_mime_header
        self.file_name_template = file_name_template
        self.suspend_message_on_file_name_generation_error = suspend_message_on_file_name_generation_error
        self.autogenerate_file_name = autogenerate_file_name
