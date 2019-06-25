# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class RegistrationDefinitionList(Model):
    """List of registration definitions.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: List of registration definitions.
    :vartype value:
     list[~azure.mgmt.managedservices.models.RegistrationDefinition]
    :ivar next_link: Link to next page of registration definitions.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RegistrationDefinition]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(RegistrationDefinitionList, self).__init__(**kwargs)
        self.value = None
        self.next_link = None
