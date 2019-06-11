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


class ErrorCount(Model):
    """The error count details.

    :param error_bucket: The error bucket.
    :type error_bucket: str
    :param count: The error count.
    :type count: int
    :param truncated: Indicates if the error count is truncated or not.
    :type truncated: bool
    """

    _attribute_map = {
        'error_bucket': {'key': 'errorBucket', 'type': 'str'},
        'count': {'key': 'count', 'type': 'int'},
        'truncated': {'key': 'truncated', 'type': 'bool'},
    }

    def __init__(self, *, error_bucket: str=None, count: int=None, truncated: bool=None, **kwargs) -> None:
        super(ErrorCount, self).__init__(**kwargs)
        self.error_bucket = error_bucket
        self.count = count
        self.truncated = truncated
