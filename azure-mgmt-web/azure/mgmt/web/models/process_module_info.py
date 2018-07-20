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


class ProcessModuleInfo(ProxyOnlyResource):
    """Process Module Information.

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
    :param base_address: Base address. Used as module identifier in ARM
     resource URI.
    :type base_address: str
    :param file_name: File name.
    :type file_name: str
    :param href: HRef URI.
    :type href: str
    :param file_path: File path.
    :type file_path: str
    :param module_memory_size: Module memory size.
    :type module_memory_size: int
    :param file_version: File version.
    :type file_version: str
    :param file_description: File description.
    :type file_description: str
    :param product: Product name.
    :type product: str
    :param product_version: Product version.
    :type product_version: str
    :param is_debug: Is debug?
    :type is_debug: bool
    :param language: Module language (locale).
    :type language: str
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
        'base_address': {'key': 'properties.base_address', 'type': 'str'},
        'file_name': {'key': 'properties.file_name', 'type': 'str'},
        'href': {'key': 'properties.href', 'type': 'str'},
        'file_path': {'key': 'properties.file_path', 'type': 'str'},
        'module_memory_size': {'key': 'properties.module_memory_size', 'type': 'int'},
        'file_version': {'key': 'properties.file_version', 'type': 'str'},
        'file_description': {'key': 'properties.file_description', 'type': 'str'},
        'product': {'key': 'properties.product', 'type': 'str'},
        'product_version': {'key': 'properties.product_version', 'type': 'str'},
        'is_debug': {'key': 'properties.is_debug', 'type': 'bool'},
        'language': {'key': 'properties.language', 'type': 'str'},
    }

    def __init__(self, kind=None, base_address=None, file_name=None, href=None, file_path=None, module_memory_size=None, file_version=None, file_description=None, product=None, product_version=None, is_debug=None, language=None):
        super(ProcessModuleInfo, self).__init__(kind=kind)
        self.base_address = base_address
        self.file_name = file_name
        self.href = href
        self.file_path = file_path
        self.module_memory_size = module_memory_size
        self.file_version = file_version
        self.file_description = file_description
        self.product = product
        self.product_version = product_version
        self.is_debug = is_debug
        self.language = language
