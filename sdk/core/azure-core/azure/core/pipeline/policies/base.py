# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import abc
import copy
import logging

from typing import (TYPE_CHECKING, Generic, TypeVar, cast, IO, List, Union, Any, Mapping, Dict, Optional,  # pylint: disable=unused-import
                    Tuple, Callable, Iterator)

from azure.core.pipeline import ABC

HTTPResponseType = TypeVar("HTTPResponseType")
HTTPRequestType = TypeVar("HTTPRequestType")

_LOGGER = logging.getLogger(__name__)


class HTTPPolicy(ABC, Generic[HTTPRequestType, HTTPResponseType]):
    """An HTTP policy ABC.

    Used with a synchronous pipeline.

    :param next: Use to process the next policy in the pipeline. Set when pipeline is
     instantiated and all policies chained.
    :type next: HTTPPolicy or HTTPTransport
    """
    def __init__(self):
        self.next = None

    @abc.abstractmethod
    def send(self, request):
        # type: (PipelineRequest[HTTPRequestType]) -> PipelineResponse[HTTPRequestType, HTTPResponseType]
        """Abstract send method for a synchronous pipeline. Mutates the request.

        Context content is dependent on the HttpTransport.

        :param request: The pipeline request object
        :type request: ~azure.core.pipeline.PipelineRequest
        :return: The pipeline response object.
        :rtype: ~azure.core.pipeline.PipelineResponse
        """

class SansIOHTTPPolicy(Generic[HTTPRequestType, HTTPResponseType]):
    """Represents a sans I/O policy.

    If a policy just modifies or annotates the request based on the HTTP
    specification, it's then a subclass of SansIOHTTPPolicy and will work
    in either Pipeline or AsyncPipeline context. This is a simple abstract
    class, that can act before the request is done, or after.
    """

    def on_request(self, request, **kwargs):
        # type: (PipelineRequest[HTTPRequestType], Any) -> None
        """Is executed before sending the request to next policy.

        :param request: Request to be modified before sent to next policy.
        :type request: ~azure.core.pipeline.PipelineRequest
        """

    def on_response(self, request, response, **kwargs):
        # type: (PipelineRequest[HTTPRequestType], PipelineResponse[HTTPRequestType, HTTPResponseType], Any) -> None
        """Is executed after the request comes back from the policy.

        :param request: Request to be modified after returning from the policy.
        :type request: ~azure.core.pipeline.PipelineRequest
        :param response: Pipeline response object
        :type response: ~azure.core.pipeline.PipelineResponse
        """

    #pylint: disable=no-self-use
    def on_exception(self, _request, **kwargs):  #pylint: disable=unused-argument
        # type: (PipelineRequest[HTTPRequestType], Any) -> bool
        """Is executed if an exception is raised while executing this policy.

        Returns True if the exception has been handled and should not
        be forwarded to the caller.

        This method is executed inside the exception handler.
        To get the exception, raise and catch it:

        .. code-block:: python

            try:
                raise
            except MyError:
                do_something()

        or use

        .. code-block:: python

            exc_type, exc_value, exc_traceback = sys.exc_info()

        :param request: The Pipeline request object
        :type request: ~azure.core.pipeline.PipelineRequest
        :return: True if exception has been handled. False if exception is
         forwarded to the caller.
        :rtype: bool
        """
        return False


class RequestHistory(object):
    """A container for an attempted request and the applicable response.

    This is used to document requests/responses that resulted in redirected/retried requests.

    :param http_request: The request.
    :type http_request: ~azure.core.pipeline.PipelineRequest
    :param http_response: The HTTP response.
    :type http_response: ~azure.core.pipeline.transport.HTTPResponse
    :param Exception error: An error encountered during the request, or None if the response was received successfully.
    :param dict context: A transport specific data container object containing data persisted between pipeline requests.
    """
    def __init__(self, http_request, http_response=None, error=None, context=None):
        # type: (PipelineRequest[HTTPRequestType], Exception, Optional[Dict[str, Any]]) -> None
        self.http_request = copy.deepcopy(http_request)
        self.http_response = http_response
        self.error = error
        self.context = context
