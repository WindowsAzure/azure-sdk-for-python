# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ApplicationListOptions(Model):
    """
    Additional parameters for the List operation.

    :param max_results: Sets the maximum number of items to return in the
     response.
    :type max_results: int
    :param timeout: Sets the maximum time that the server can spend
     processing the request, in seconds. The default is 30 seconds. Default
     value: 30 .
    :type timeout: int
    :param client_request_id: Caller generated request identity, in the form
     of a GUID with no decoration such as curly braces e.g.
     9C4D50EE-2D56-4CD3-8152-34347DC9F2B0.
    :type client_request_id: str
    :param return_client_request_id: Specifies if the server should return
     the client-request-id identifier in the response.
    :type return_client_request_id: bool
    :param ocp_date: The time the request was issued. If not specified, this
     header will be automatically populated with the current system clock
     time.
    :type ocp_date: datetime
    """ 

    def __init__(self, max_results=None, timeout=30, client_request_id=None, return_client_request_id=None, ocp_date=None):
        self.max_results = max_results
        self.timeout = timeout
        self.client_request_id = client_request_id
        self.return_client_request_id = return_client_request_id
        self.ocp_date = ocp_date
