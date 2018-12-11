# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class Userargs(Model):
    """Gets or sets the object containing the user arguments.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar arg: The list of args defined by the user.
    :vartype arg: list[str]
    :param callback: The callback URL, if any.
    :type callback: object
    :ivar define: The define properties defined by the user.
    :vartype define: list[str]
    :param enablelog: Whether or not the user enabled logs.
    :type enablelog: str
    :param execute: The query defined by the user.
    :type execute: str
    :param file: The query file provided by the user.
    :type file: object
    :param files: The files defined by the user.
    :type files: object
    :param jar: The JAR file provided by the user.
    :type jar: str
    :param statusdir: The status directory defined by the user.
    :type statusdir: object
    """

    _validation = {
        'arg': {'readonly': True},
        'define': {'readonly': True},
    }

    _attribute_map = {
        'arg': {'key': 'arg', 'type': '[str]'},
        'callback': {'key': 'callback', 'type': 'object'},
        'define': {'key': 'define', 'type': '[str]'},
        'enablelog': {'key': 'enablelog', 'type': 'str'},
        'execute': {'key': 'execute', 'type': 'str'},
        'file': {'key': 'file', 'type': 'object'},
        'files': {'key': 'files', 'type': 'object'},
        'jar': {'key': 'jar', 'type': 'str'},
        'statusdir': {'key': 'statusdir', 'type': 'object'},
    }

    def __init__(self, *, callback=None, enablelog: str=None, execute: str=None, file=None, files=None, jar: str=None, statusdir=None, **kwargs) -> None:
        super(Userargs, self).__init__(**kwargs)
        self.arg = None
        self.callback = callback
        self.define = None
        self.enablelog = enablelog
        self.execute = execute
        self.file = file
        self.files = files
        self.jar = jar
        self.statusdir = statusdir
