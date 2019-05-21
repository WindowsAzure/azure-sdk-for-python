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


class MonitoringDetails(Model):
    """Details needed to monitor a Hana Instance.

    :param hana_subnet: ARM ID of an Azure Subnet with access to the HANA
     instance.
    :type hana_subnet: str
    :param hana_hostname: Hostname of the HANA Instance blade.
    :type hana_hostname: str
    :param hana_db_name: Name of the database itself.
    :type hana_db_name: str
    :param hana_db_sql_port: The port number of the tenant DB. Used to connect
     to the DB.
    :type hana_db_sql_port: int
    :param hana_db_username: Username for the HANA database to login to for
     monitoring
    :type hana_db_username: str
    :param hana_db_password: Password for the HANA database to login for
     monitoring
    :type hana_db_password: str
    """

    _attribute_map = {
        'hana_subnet': {'key': 'hanaSubnet', 'type': 'str'},
        'hana_hostname': {'key': 'hanaHostname', 'type': 'str'},
        'hana_db_name': {'key': 'hanaDbName', 'type': 'str'},
        'hana_db_sql_port': {'key': 'hanaDbSqlPort', 'type': 'int'},
        'hana_db_username': {'key': 'hanaDbUsername', 'type': 'str'},
        'hana_db_password': {'key': 'hanaDbPassword', 'type': 'str'},
    }

    def __init__(self, *, hana_subnet: str=None, hana_hostname: str=None, hana_db_name: str=None, hana_db_sql_port: int=None, hana_db_username: str=None, hana_db_password: str=None, **kwargs) -> None:
        super(MonitoringDetails, self).__init__(**kwargs)
        self.hana_subnet = hana_subnet
        self.hana_hostname = hana_hostname
        self.hana_db_name = hana_db_name
        self.hana_db_sql_port = hana_db_sql_port
        self.hana_db_username = hana_db_username
        self.hana_db_password = hana_db_password
