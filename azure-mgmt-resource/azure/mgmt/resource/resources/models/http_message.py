# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class HttpMessage(Model):
    """HttpMessage

    :param content: Gets or sets HTTP message content.
    :type content: object
    """ 

    _attribute_map = {
        'content': {'key': 'content', 'type': 'object'},
    }

    def __init__(self, content=None):
        self.content = content
