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


class SoaRecord(Model):
    """An SOA record.

    :param host: The domain name of the authoritative name server for this SOA
     record.
    :type host: str
    :param email: The email contact for this SOA record.
    :type email: str
    :param serial_number: The serial number for this SOA record.
    :type serial_number: long
    :param refresh_time: The refresh value for this SOA record.
    :type refresh_time: long
    :param retry_time: The retry time for this SOA record.
    :type retry_time: long
    :param expire_time: The expire time for this SOA record.
    :type expire_time: long
    :param minimum_ttl: The minimum value for this SOA record. By convention
     this is used to determine the negative caching duration.
    :type minimum_ttl: long
    """

    _attribute_map = {
        'host': {'key': 'host', 'type': 'str'},
        'email': {'key': 'email', 'type': 'str'},
        'serial_number': {'key': 'serialNumber', 'type': 'long'},
        'refresh_time': {'key': 'refreshTime', 'type': 'long'},
        'retry_time': {'key': 'retryTime', 'type': 'long'},
        'expire_time': {'key': 'expireTime', 'type': 'long'},
        'minimum_ttl': {'key': 'minimumTtl', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(SoaRecord, self).__init__(**kwargs)
        self.host = kwargs.get('host', None)
        self.email = kwargs.get('email', None)
        self.serial_number = kwargs.get('serial_number', None)
        self.refresh_time = kwargs.get('refresh_time', None)
        self.retry_time = kwargs.get('retry_time', None)
        self.expire_time = kwargs.get('expire_time', None)
        self.minimum_ttl = kwargs.get('minimum_ttl', None)
