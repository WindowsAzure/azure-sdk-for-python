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
from typing import List, Union, Optional, TypeVar, Callable
from azure.core.pipeline.policies import AsyncHTTPPolicy, SansIOHTTPPolicy
from azure.core.exceptions import (
    ServiceRequestError,
    ServiceResponseError
)
import requests
from msrest.serialization import Model # type: ignore # pylint: disable=unused-import

AsyncHTTPResponseType = TypeVar("AsyncHTTPResponseType")
HTTPRequestType = TypeVar("HTTPRequestType")

ErrorType = Optional[Union[ServiceRequestError, ServiceResponseError]]
ImplPoliciesType = List[AsyncHTTPPolicy[HTTPRequestType, AsyncHTTPResponseType]] #pylint: disable=unsubscriptable-object
PoliciesType = List[Union[AsyncHTTPPolicy, SansIOHTTPPolicy]]
DeserializationCallbackType = Union[Model, Callable[[requests.Response], Model]]
