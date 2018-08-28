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


class PrebuiltDomainCreateBaseObject(Model):
    """A model object containing the name of the custom prebuilt entity and the
    name of the domain to which this model belongs.

    :param domain_name: The domain name.
    :type domain_name: str
    """

    _attribute_map = {
        'domain_name': {'key': 'domainName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PrebuiltDomainCreateBaseObject, self).__init__(**kwargs)
        self.domain_name = kwargs.get('domain_name', None)
