# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .adls_remote_exception import AdlsRemoteException


class AdlsSecurityException(AdlsRemoteException):
    """
    A WebHDFS exception thrown indicating that access is denied. Thrown when a
    401 error response code is returned (Unauthorized).

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar java_class_name: the full class package name for the exception
     thrown, such as 'java.lang.IllegalArgumentException'.
    :vartype java_class_name: str
    :ivar message: the message associated with the exception that was thrown,
     such as 'Invalid value for webhdfs parameter "permission":...'.
    :vartype message: str
    :param exception: Polymorphic Discriminator
    :type exception: str
    """ 

    _validation = {
        'java_class_name': {'readonly': True},
        'message': {'readonly': True},
        'exception': {'required': True},
    }

    def __init__(self):
        super(AdlsSecurityException, self).__init__()
        self.exception = 'SecurityException'
