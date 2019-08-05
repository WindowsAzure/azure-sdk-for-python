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


class InvoiceSectionCreationRequest(Model):
    """The properties of an InvoiceSection.

    :param display_name: The name of the InvoiceSection.
    :type display_name: str
    """

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
    }

    def __init__(self, *, display_name: str=None, **kwargs) -> None:
        super(InvoiceSectionCreationRequest, self).__init__(**kwargs)
        self.display_name = display_name
