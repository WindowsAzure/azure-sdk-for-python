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

from .resource import Resource


class CertificateEmail(Resource):
    """SSL certificate email.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :param email_id: Email id.
    :type email_id: str
    :param time_stamp: Time stamp.
    :type time_stamp: datetime
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'email_id': {'key': 'properties.emailId', 'type': 'str'},
        'time_stamp': {'key': 'properties.timeStamp', 'type': 'iso-8601'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None, email_id=None, time_stamp=None):
        super(CertificateEmail, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.email_id = email_id
        self.time_stamp = time_stamp
