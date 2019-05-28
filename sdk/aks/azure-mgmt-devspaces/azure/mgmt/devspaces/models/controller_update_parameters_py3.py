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


class ControllerUpdateParameters(Model):
    """Parameters for updating an Azure Dev Spaces Controller.

    :param tags: Tags for the Azure Dev Spaces Controller.
    :type tags: dict[str, str]
    :param target_container_host_credentials_base64: Credentials of the target
     container host (base64).
    :type target_container_host_credentials_base64: str
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'target_container_host_credentials_base64': {'key': 'properties.targetContainerHostCredentialsBase64', 'type': 'str'},
    }

    def __init__(self, *, tags=None, target_container_host_credentials_base64: str=None, **kwargs) -> None:
        super(ControllerUpdateParameters, self).__init__(**kwargs)
        self.tags = tags
        self.target_container_host_credentials_base64 = target_container_host_credentials_base64
