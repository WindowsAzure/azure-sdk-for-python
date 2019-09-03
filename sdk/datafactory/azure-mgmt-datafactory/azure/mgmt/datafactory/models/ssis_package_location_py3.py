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


class SSISPackageLocation(Model):
    """SSIS package location.

    All required parameters must be populated in order to send to Azure.

    :param package_path: Required. The SSIS package path. Type: string (or
     Expression with resultType string).
    :type package_path: object
    :param type: The type of SSIS package location. Possible values include:
     'SSISDB', 'File'
    :type type: str or ~azure.mgmt.datafactory.models.SsisPackageLocationType
    :param package_password: Password of the package.
    :type package_password: ~azure.mgmt.datafactory.models.SecureString
    :param access_credential: The package access credential.
    :type access_credential:
     ~azure.mgmt.datafactory.models.SSISAccessCredential
    :param configuration_path: The configuration file of the package
     execution. Type: string (or Expression with resultType string).
    :type configuration_path: object
    """

    _validation = {
        'package_path': {'required': True},
    }

    _attribute_map = {
        'package_path': {'key': 'packagePath', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'package_password': {'key': 'typeProperties.packagePassword', 'type': 'SecureString'},
        'access_credential': {'key': 'typeProperties.accessCredential', 'type': 'SSISAccessCredential'},
        'configuration_path': {'key': 'typeProperties.configurationPath', 'type': 'object'},
    }

    def __init__(self, *, package_path, type=None, package_password=None, access_credential=None, configuration_path=None, **kwargs) -> None:
        super(SSISPackageLocation, self).__init__(**kwargs)
        self.package_path = package_path
        self.type = type
        self.package_password = package_password
        self.access_credential = access_credential
        self.configuration_path = configuration_path
