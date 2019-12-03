#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# This script is intended to be a place holder for common tasks that are requried by scripts running on tox

import logging
import argparse
import ast
import os
import textwrap
import io
import glob
import zipfile

logging.getLogger().setLevel(logging.INFO)

root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "..", ".."))

def get_package_details(setup_filename):
    mock_setup = textwrap.dedent(
        """\
    def setup(*args, **kwargs):
        __setup_calls__.append((args, kwargs))
    """
    )
    parsed_mock_setup = ast.parse(mock_setup, filename=setup_filename)
    with io.open(setup_filename, "r", encoding="utf-8-sig") as setup_file:
        parsed = ast.parse(setup_file.read())
        for index, node in enumerate(parsed.body[:]):
            if (
                not isinstance(node, ast.Expr)
                or not isinstance(node.value, ast.Call)
                or not hasattr(node.value.func, "id")
                or node.value.func.id != "setup"
            ):
                continue
            parsed.body[index:index] = parsed_mock_setup.body
            break

    fixed = ast.fix_missing_locations(parsed)
    codeobj = compile(fixed, setup_filename, "exec")
    local_vars = {}
    global_vars = {"__setup_calls__": []}
    current_dir = os.getcwd()
    working_dir = os.path.dirname(setup_filename)
    os.chdir(working_dir)
    exec(codeobj, global_vars, local_vars)
    os.chdir(current_dir)
    _, kwargs = global_vars["__setup_calls__"][0]

    package_name = kwargs["name"]
    # default namespace for the package
    name_space = package_name.replace('-', '.')
    if "packages" in kwargs.keys():
        packages = kwargs["packages"]
        if packages:
            name_space = packages[0]
            logging.info("Namespaces found for package {0}: {1}".format(package_name, packages))

    return package_name, name_space, kwargs["version"]

def unzip_sdist_to_directory(containing_folder):
    # grab the first one
    path_to_zip_file = glob.glob(os.path.join(containing_folder, "*.zip"))[0]
    return unzip_file_to_directory(path_to_zip_file, containing_folder)

def unzip_file_to_directory(path_to_zip_file, extract_location):
    # unzip file in given path
    # dump into given path
    with zipfile.ZipFile(path_to_zip_file, "r") as zip_ref:
        zip_ref.extractall(extract_location)
        extracted_dir = os.path.basename(os.path.splitext(path_to_zip_file)[0])
        return os.path.join(extract_location, extracted_dir)

def move_and_rename(source_location):
    new_location = os.path.join(os.path.dirname(source_location), "unzipped")
    os.rename(source_location, new_location)

    return new_location
