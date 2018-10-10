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
from msrest.exceptions import HttpOperationError


class WorkItemConfigurationError(Model):
    """Error associated with trying to get work item configuration or
    configurations.

    :param code: Error detail code and explanation
    :type code: str
    :param message: Error message
    :type message: str
    :param innererror:
    :type innererror: ~azure.mgmt.applicationinsights.models.InnerError
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'innererror': {'key': 'innererror', 'type': 'InnerError'},
    }

    def __init__(self, **kwargs):
        super(WorkItemConfigurationError, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)
        self.innererror = kwargs.get('innererror', None)


class WorkItemConfigurationErrorException(HttpOperationError):
    """Server responsed with exception of type: 'WorkItemConfigurationError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(WorkItemConfigurationErrorException, self).__init__(deserialize, response, 'WorkItemConfigurationError', *args)
