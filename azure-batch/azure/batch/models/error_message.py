# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ErrorMessage(Model):
    """
    An error message received in an Azure Batch error response.

    :param lang: Gets or sets the language code of the error message
    :type lang: str
    :param value: Gets or sets the text of the message.
    :type value: str
    """ 

    _attribute_map = {
        'lang': {'key': 'lang', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, lang=None, value=None):
        self.lang = lang
        self.value = value
