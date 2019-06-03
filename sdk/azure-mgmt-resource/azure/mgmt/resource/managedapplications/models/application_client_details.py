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


class ApplicationClientDetails(Model):
    """The application client details to track the entity creating/updating the
    managed app resource.

    :param oid: The client Oid.
    :type oid: str
    :param puid: The client Puid
    :type puid: str
    :param application_id: The client application Id.
    :type application_id: str
    """

    _attribute_map = {
        'oid': {'key': 'Oid', 'type': 'str'},
        'puid': {'key': 'Puid', 'type': 'str'},
        'application_id': {'key': 'ApplicationId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationClientDetails, self).__init__(**kwargs)
        self.oid = kwargs.get('oid', None)
        self.puid = kwargs.get('puid', None)
        self.application_id = kwargs.get('application_id', None)
