# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class JobTerminateParameter(Model):
    """
    Parameters for a CloudJobOperations.Terminate request.

    :param terminate_reason: Sets the text you want to appear as the job's
     TerminateReason. The default is 'UserTerminate'.
    :type terminate_reason: str
    """ 

    _attribute_map = {
        'terminate_reason': {'key': 'terminateReason', 'type': 'str'},
    }

    def __init__(self, terminate_reason=None):
        self.terminate_reason = terminate_reason
