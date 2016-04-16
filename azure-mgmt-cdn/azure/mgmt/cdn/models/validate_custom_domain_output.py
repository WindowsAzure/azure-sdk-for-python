# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ValidateCustomDomainOutput(Model):
    """
    Output of custom domain validation.

    :param custom_domain_validated: Indicates whether the custom domain is
     validated or not.
    :type custom_domain_validated: bool
    :param reason: The reason why the custom domain is not valid.
    :type reason: str
    :param message: The message describing why the custom domain is not valid.
    :type message: str
    """ 

    _attribute_map = {
        'custom_domain_validated': {'key': 'customDomainValidated', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, custom_domain_validated=None, reason=None, message=None):
        self.custom_domain_validated = custom_domain_validated
        self.reason = reason
        self.message = message
