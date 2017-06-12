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


class AzureIaaSVMErrorInfo(Model):
    """Azure IaaS VM workload-specific error information.

    :param error_code: Error code.
    :type error_code: int
    :param error_title: Title: Typically, the entity that the error pertains
     to.
    :type error_title: str
    :param error_string: Localized error string.
    :type error_string: str
    :param recommendations: List of localized recommendations for above error
     code.
    :type recommendations: list of str
    """

    _attribute_map = {
        'error_code': {'key': 'errorCode', 'type': 'int'},
        'error_title': {'key': 'errorTitle', 'type': 'str'},
        'error_string': {'key': 'errorString', 'type': 'str'},
        'recommendations': {'key': 'recommendations', 'type': '[str]'},
    }

    def __init__(self, error_code=None, error_title=None, error_string=None, recommendations=None):
        self.error_code = error_code
        self.error_title = error_title
        self.error_string = error_string
        self.recommendations = recommendations
