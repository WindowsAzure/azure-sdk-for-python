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


class ImageTemplateUpdateParameters(Model):
    """Parameters for updating an image template.

    :param identity: The identity of the image template, if configured.
    :type identity: ~azure.mgmt.imagebuilder.models.ImageTemplateIdentity
    :param tags: The user-specified tags associated with the image template.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'identity': {'key': 'identity', 'type': 'ImageTemplateIdentity'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, identity=None, tags=None, **kwargs) -> None:
        super(ImageTemplateUpdateParameters, self).__init__(**kwargs)
        self.identity = identity
        self.tags = tags
