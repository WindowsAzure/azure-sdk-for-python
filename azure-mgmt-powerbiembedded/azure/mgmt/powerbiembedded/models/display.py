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


class Display(Model):
    """Display.

    :param provider: The localized friendly form of the resource provider
     name. This form is also expected to include the publisher/company
     responsible. Use Title Casing. Begin with "Microsoft" for 1st party
     services.
    :type provider: str
    :param resource: The localized friendly form of the resource type related
     to this action/operation. This form should match the public documentation
     for the resource provider. Use Title Casing. For examples, refer to the
     "name" section.
    :type resource: str
    :param operation: The localized friendly name for the operation as shown
     to the user. This name should be concise (to fit in drop downs), but clear
     (self-documenting). Use Title Casing and include the entity/resource to
     which it applies.
    :type operation: str
    :param description: The localized friendly description for the operation
     as shown to the user. This description should be thorough, yet concise. It
     will be used in tool-tips and detailed views.
    :type description: str
    :param origin: The intended executor of the operation; governs the display
     of the operation in the RBAC UX and the audit logs UX. Default value is
     'user,system'
    :type origin: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'origin': {'key': 'origin', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Display, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)
        self.origin = kwargs.get('origin', None)
