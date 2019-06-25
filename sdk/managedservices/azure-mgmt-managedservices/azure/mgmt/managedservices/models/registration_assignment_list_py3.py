# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class RegistrationAssignmentList(Model):
    """List of registration assignments.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: List of registration assignments.
    :vartype value:
     list[~azure.mgmt.managedservices.models.RegistrationAssignment]
    :ivar next_link: Link to next page of registration assignments.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RegistrationAssignment]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(RegistrationAssignmentList, self).__init__(**kwargs)
        self.value = None
        self.next_link = None
