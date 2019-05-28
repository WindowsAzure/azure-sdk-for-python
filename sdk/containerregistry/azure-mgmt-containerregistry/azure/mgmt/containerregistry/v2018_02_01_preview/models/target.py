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


class Target(Model):
    """The target of the event.

    :param media_type: The MIME type of the referenced object.
    :type media_type: str
    :param size: The number of bytes of the content. Same as Length field.
    :type size: long
    :param digest: The digest of the content, as defined by the Registry V2
     HTTP API Specification.
    :type digest: str
    :param length: The number of bytes of the content. Same as Size field.
    :type length: long
    :param repository: The repository name.
    :type repository: str
    :param url: The direct URL to the content.
    :type url: str
    :param tag: The tag name.
    :type tag: str
    :param name: The name of the artifact.
    :type name: str
    :param version: The version of the artifact.
    :type version: str
    """

    _attribute_map = {
        'media_type': {'key': 'mediaType', 'type': 'str'},
        'size': {'key': 'size', 'type': 'long'},
        'digest': {'key': 'digest', 'type': 'str'},
        'length': {'key': 'length', 'type': 'long'},
        'repository': {'key': 'repository', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'tag': {'key': 'tag', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Target, self).__init__(**kwargs)
        self.media_type = kwargs.get('media_type', None)
        self.size = kwargs.get('size', None)
        self.digest = kwargs.get('digest', None)
        self.length = kwargs.get('length', None)
        self.repository = kwargs.get('repository', None)
        self.url = kwargs.get('url', None)
        self.tag = kwargs.get('tag', None)
        self.name = kwargs.get('name', None)
        self.version = kwargs.get('version', None)
