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


class ApplicationPackageReference(Model):
    """Link to an application package inside the batch account.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. The ID of the application package to install. This
     must be inside the same batch account as the pool. This can either be a
     reference to a specific version or the default version if one exists.
    :type id: str
    :param version: The version of the application to deploy. If omitted, the
     default version is deployed. If this is omitted, and no default version is
     specified for this application, the request fails with the error code
     InvalidApplicationPackageReferences. If you are calling the REST API
     directly, the HTTP status code is 409.
    :type version: str
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationPackageReference, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.version = kwargs.get('version', None)
