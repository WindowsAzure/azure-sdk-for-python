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


class DpmErrorInfo(Model):
    """DPM workload-specific error information.

    :param error_string: Localized error string.
    :type error_string: str
    :param recommendations: List of localized recommendations for above error
     code.
    :type recommendations: list[str]
    """

    _attribute_map = {
        'error_string': {'key': 'errorString', 'type': 'str'},
        'recommendations': {'key': 'recommendations', 'type': '[str]'},
    }

    def __init__(self, *, error_string: str=None, recommendations=None, **kwargs) -> None:
        super(DpmErrorInfo, self).__init__(**kwargs)
        self.error_string = error_string
        self.recommendations = recommendations
