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


class DistcpSettings(Model):
    """Distcp settings.

    All required parameters must be populated in order to send to Azure.

    :param resource_manager_endpoint: Required. Specifies the Yarn
     ResourceManager endpoint. Type: string (or Expression with resultType
     string).
    :type resource_manager_endpoint: object
    :param temp_script_path: Required. Specifies an existing folder path which
     will be used to store temp Distcp command script. The script file is
     generated by ADF and will be removed after Copy job finished. Type: string
     (or Expression with resultType string).
    :type temp_script_path: object
    :param distcp_options: Specifies the Distcp options. Type: string (or
     Expression with resultType string).
    :type distcp_options: object
    """

    _validation = {
        'resource_manager_endpoint': {'required': True},
        'temp_script_path': {'required': True},
    }

    _attribute_map = {
        'resource_manager_endpoint': {'key': 'resourceManagerEndpoint', 'type': 'object'},
        'temp_script_path': {'key': 'tempScriptPath', 'type': 'object'},
        'distcp_options': {'key': 'distcpOptions', 'type': 'object'},
    }

    def __init__(self, *, resource_manager_endpoint, temp_script_path, distcp_options=None, **kwargs) -> None:
        super(DistcpSettings, self).__init__(**kwargs)
        self.resource_manager_endpoint = resource_manager_endpoint
        self.temp_script_path = temp_script_path
        self.distcp_options = distcp_options
