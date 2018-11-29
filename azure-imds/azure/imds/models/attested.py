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


class Attested(Model):
    """This is the response from the Attested_GetDocument operation.

    :param signature: This is the encoded string containing the VM ID, plan
     information, and nonce value.
    :type signature: str
    :param encoding: This is the encoding scheme of the signature.
    :type encoding: str
    """

    _attribute_map = {
        'signature': {'key': 'signature', 'type': 'str'},
        'encoding': {'key': 'encoding', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Attested, self).__init__(**kwargs)
        self.signature = kwargs.get('signature', None)
        self.encoding = kwargs.get('encoding', None)
