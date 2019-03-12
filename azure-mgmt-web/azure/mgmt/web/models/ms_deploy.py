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

from .proxy_only_resource import ProxyOnlyResource


class MSDeploy(ProxyOnlyResource):
    """MSDeploy ARM PUT information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param package_uri: Package URI
    :type package_uri: str
    :param connection_string: SQL Connection String
    :type connection_string: str
    :param db_type: Database Type
    :type db_type: str
    :param set_parameters_xml_file_uri: URI of MSDeploy Parameters file. Must
     not be set if SetParameters is used.
    :type set_parameters_xml_file_uri: str
    :param set_parameters: MSDeploy Parameters. Must not be set if
     SetParametersXmlFileUri is used.
    :type set_parameters: dict[str, str]
    :param skip_app_data: Controls whether the MSDeploy operation skips the
     App_Data directory.
     If set to <code>true</code>, the existing App_Data directory on the
     destination
     will not be deleted, and any App_Data directory in the source will be
     ignored.
     Setting is <code>false</code> by default.
    :type skip_app_data: bool
    :param app_offline: Sets the AppOffline rule while the MSDeploy operation
     executes.
     Setting is <code>false</code> by default.
    :type app_offline: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'package_uri': {'key': 'properties.packageUri', 'type': 'str'},
        'connection_string': {'key': 'properties.connectionString', 'type': 'str'},
        'db_type': {'key': 'properties.dbType', 'type': 'str'},
        'set_parameters_xml_file_uri': {'key': 'properties.setParametersXmlFileUri', 'type': 'str'},
        'set_parameters': {'key': 'properties.setParameters', 'type': '{str}'},
        'skip_app_data': {'key': 'properties.skipAppData', 'type': 'bool'},
        'app_offline': {'key': 'properties.appOffline', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(MSDeploy, self).__init__(**kwargs)
        self.package_uri = kwargs.get('package_uri', None)
        self.connection_string = kwargs.get('connection_string', None)
        self.db_type = kwargs.get('db_type', None)
        self.set_parameters_xml_file_uri = kwargs.get('set_parameters_xml_file_uri', None)
        self.set_parameters = kwargs.get('set_parameters', None)
        self.skip_app_data = kwargs.get('skip_app_data', None)
        self.app_offline = kwargs.get('app_offline', None)
