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


class HiveJobStatementInfo(Model):
    """HiveJobStatementInfo.

    :param log_location: Gets or sets the log location for this statement.
    :type log_location: str
    :param result_preview_location: Gets or sets the result preview location
     for this statement.
    :type result_preview_location: str
    :param result_location: Gets or sets the result location for this
     statement.
    :type result_location: str
    :param error_message: Gets or sets the error message for this statement.
    :type error_message: str
    """ 

    _attribute_map = {
        'log_location': {'key': 'logLocation', 'type': 'str'},
        'result_preview_location': {'key': 'resultPreviewLocation', 'type': 'str'},
        'result_location': {'key': 'resultLocation', 'type': 'str'},
        'error_message': {'key': 'errorMessage', 'type': 'str'},
    }

    def __init__(self, log_location=None, result_preview_location=None, result_location=None, error_message=None):
        self.log_location = log_location
        self.result_preview_location = result_preview_location
        self.result_location = result_location
        self.error_message = error_message
