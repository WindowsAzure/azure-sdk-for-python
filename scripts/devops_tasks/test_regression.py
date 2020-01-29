#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# This script will run regression test for packages which are added as required package by other packages
# Regression test ensures backword compatibility with released dependent package versions

import argparse
import glob
import sys
import os
import logging
from common_tasks import process_glob_string, parse_setup, run_check_call, parse_require, install_package_from_whl, filter_dev_requirements, OmmitType
from git_helper import get_release_tag, checkout_code_repo, clone_repo

AZURE_GLOB_STRING = "azure*"

root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "..", ".."))
test_tools_req_file = os.path.abspath(os.path.join(root_dir, "eng", "test_tools.txt"))

GIT_REPO_NAME = "azure-sdk-for-python"
GIT_MASTER_BRANCH = "master"
VENV_NAME = "regressionenv"
AZURE_SDK_FOR_PYTHON_GIT_URL = "https://github.com/Azure/azure-sdk-for-python.git"
TEMP_FOLDER_NAME = ".tmp_code_path"
COSMOS_TEST_ARG = 'not cosmosEmulator'

logging.getLogger().setLevel(logging.INFO)

def run_regression_test(pkg_name, dep_packages, whl_directory, isLatestDepend, tmp_path, working_dir):

    # pkg_name: Name of the package for which regression is tested
    # dep_packages: List of path to packages in code repo which takes <package-name> as dependency
    # whl_directory: directory (passed as paremeter) in which whl for <package-name> is available
    # tmp_path: Temporary path passed as parameter to clone code repo to run test
    # isLatestDepend: Passed as true or false to run regression using latest or oldest released version of dependent package

    venv_path = os.path.join(tmp_path, VENV_NAME)
    #create a virtual environment to run test
    create_virtual_env(venv_path)
    python_sym_link = os.path.abspath(os.path.join(venv_path, "Scripts", "python"))

    logging.info("Dependent packages for [{0}]: {1}".format(pkg_name, dep_packages))
    # Run test for each dependent package in its own virtual environment
    for dep_pkg_path in dep_packages:
        dep_pkg_name, _, _, _ = parse_setup(dep_pkg_path)
        logging.info("Starting regression test of {0} against released {1}".format(pkg_name, dep_pkg_name))
        pre_test_step(dep_pkg_path, whl_directory, pkg_name, venv_path, working_dir, python_sym_link)
        try:
            run_test(dep_pkg_path, pkg_name, isLatestDepend, python_sym_link)
        finally:
            post_test_step(venv_path, dep_pkg_path, python_sym_link)
        logging.info("Completed regression test of {0} against released {1}".format(pkg_name, dep_pkg_name))


def pre_test_step(dependent_pkg_path, whl_directory, pkg_name, venv_path, working_dir, python_sym_link):
    # This function will execute any pre step required before running test for individual dependent packages
    # pre steps are like: checking out master branch to revert code repo
    # start and activate new virtual environment
    # install pre build whl for the package for which regression is tested. (for e.g. azure-core)
    logging.info("Running pre-run-step for package: {}".format(dependent_pkg_path))
    # activate virtual env and change working directory to package root
    process_virtual_env(True, venv_path, python_sym_link)
    # install packages required to run tests after updating relative referefnce to abspath
    install_requirements(test_tools_req_file, working_dir, python_sym_link)
    # Install pre-built whl for current package
    install_package_from_whl(pkg_name, whl_directory, root_dir, python_sym_link)

def get_package_test_path(pkg_root_path):
    paths = glob.glob(os.path.join(pkg_root_path, "test*"))
    if paths is None:
        logging.error("'test' folder is not found in {}".format(pkg_root_path))
        sys.exit(1)
    return paths[0]

def run_test(dependent_pkg_path, package_name, isLatest, python_sym_link):
    # find GA released tags for package and run test using that code base
    dep_pkg_name, _, _, _ = parse_setup(dependent_pkg_path)
    release_tag = get_release_tag(dep_pkg_name, isLatest)
    if not release_tag:
        logging.info("Skipping package {} from test since release tag is not avaiable".format(dep_pkg_name))
        return

    # checkout git hub repo with release tag    
    checkout_code_repo(release_tag, dependent_pkg_path)
    
    # install dependent package from source
    install_packages(dependent_pkg_path, package_name, python_sym_link)
    logging.info("Running test for {}".format(dependent_pkg_path))
    pkg_test_path = get_package_test_path(dependent_pkg_path)
    run_check_call([python_sym_link, "-m", "pytest", "--verbose", "-m", COSMOS_TEST_ARG, pkg_test_path], root_dir)


def install_packages(dependent_pkg_path, package_name, python_sym_link):
     # install dev requirement but skip already installed package which is being tested
    filtered_dev_req_path = filter_dev_requirements(dependent_pkg_path, [package_name,], dependent_pkg_path)
    logging.info("Installing filtered dev requirements from {}".format(filtered_dev_req_path))
    install_requirements(filtered_dev_req_path, dependent_pkg_path, python_sym_link)    
    # install dependent package which is being verified
    run_check_call([python_sym_link, "-m", "pip", "install", dependent_pkg_path], root_dir)   


def post_test_step(venv_path, dependent_pkg_path, python_sym_link):
    # This function can be used to reset code repo to master branch and also to deactivate virtual env
    # revert to master branch
    run_check_call(["git", "clean", "-fd"], dependent_pkg_path)
    run_check_call(["git", "checkout", GIT_MASTER_BRANCH], dependent_pkg_path)
    process_virtual_env(False, venv_path, python_sym_link)


def process_virtual_env(activate_env, venv_path, python_sym_link):
    # for now this will work only on Windows. I will update this to make it platform independent
    if activate_env:
        # clear any previously installed packages
        run_check_call([sys.executable, "-m", "venv", "--clear", "ENV_DIR", venv_path], root_dir)

    scriptName = "activate.bat" if activate_env else "deactivate.bat"
    venv_script = os.path.join(venv_path, "Scripts", scriptName)
    operation_type = "Activating" if activate_env else "Deactivating"

    if os.path.exists(venv_script):
        logging.info("{0} virtual environment {1}".format(operation_type, venv_script))
        run_check_call([venv_script,], root_dir)
    else:
        logging.error("Script to process virtualenv is missing. path [{}]".format(venv_script))
        sys.exit(1)
    

def create_virtual_env(venv_path):
    logging.info("Creating virtual environment [{}]".format(venv_path))
    run_check_call([sys.executable, "-m", "venv", "ENV_DIR", venv_path], root_dir)


def install_requirements(req_path, working_dir, python_sym_link):
    # install packages required to run tests
    run_check_call([python_sym_link, "-m", "pip", "install", "-r", req_path], working_dir)   


# This method identifies package dependency map for all packages in azure sdk
def find_package_dependency(glob_string, repo_root_dir):
    package_paths = process_glob_string(glob_string, repo_root_dir, "", OmmitType.Regression)
    dependency_map = {}
    for pkg_root in package_paths:
        dependent_pkg_name, _, _, requires = parse_setup(pkg_root)
        # todo: This should be removed once issue in storage file share test is resolved
        if "cosmos" not in dependent_pkg_name:
            continue
        # Get a list of package names from install requires
        required_pkgs = [parse_require(r)[0] for r in requires]
        required_pkgs = [p for p in required_pkgs if p.startswith("azure")]

        for req_pkg in required_pkgs:
            if req_pkg not in dependency_map:
                dependency_map[req_pkg] = []
            dependency_map[req_pkg].append(pkg_root)

    logging.info("Package dependency: {}".format(dependency_map))
    return dependency_map


# This is the main function which identifies packages to test, find dependency matrix and trigger test
def run_main(args):

    temp_dir = ""
    if args.temp_dir:
        temp_dir = args.temp_dir
    else:
        temp_dir = os.path.abspath(os.path.join(root_dir, "..", TEMP_FOLDER_NAME))

    core_repo_root = os.path.join(temp_dir, GIT_REPO_NAME)
    # Make sure root_dir where script is running is not same as code repo which will be reverted to old released branch to run test
    if root_dir == core_repo_root:
        logging.error("Invalid path to clone github code repo. Temporary path can not be same as current source root directory")
        exit(1)

    # Make sure temp path exists
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)

    if args.service:
        service_dir = os.path.join("sdk", args.service)
        target_dir = os.path.join(root_dir, service_dir)
    else:
        target_dir = root_dir

    targeted_packages = process_glob_string(args.glob_string, target_dir)
    if len(targeted_packages) == 0:
        exit(0)
       
    # clone code repo only if it doesn't exists
    if not os.path.exists(core_repo_root):
        clone_repo(temp_dir, AZURE_SDK_FOR_PYTHON_GIT_URL)
    else:
        logging.info("Path {} already exists. Skipping step to clone github repo".format(core_repo_root))

    # find package dependency map for azure sdk
    pkg_dependency = find_package_dependency(AZURE_GLOB_STRING, core_repo_root)
    logging.info("Regression test will run for: {}".format(pkg_dependency.keys()))
    for pkg_path in targeted_packages:
        package_name, _, _, _ = parse_setup(pkg_path)
        if package_name in pkg_dependency:
            logging.info("Running regression test for {}".format(package_name))
            run_regression_test(package_name, pkg_dependency[package_name], args.whl_dir, args.verify_latest, temp_dir, pkg_path)
            logging.info("Completed regression test for {}".format(package_name))

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run regression test for a package against released dependent packages"
    )

    parser.add_argument(
        "glob_string",
        nargs="?",
        help=(
            "A comma separated list of glob strings that will target the top level directories that contain packages."
            'Examples: All = "azure*", Single = "azure-keyvault", Targeted Multiple = "azure-keyvault,azure-mgmt-resource"'
        ),
    )

    parser.add_argument(
        "--service",
        help=(
            "Name of service directory (under sdk/) to test."
            "Example: --service applicationinsights"
        ),
    )

    parser.add_argument(
        "--whl-dir",
        required=True,
        help=(
            "Directory in which whl is pre built for all eligible package"
        ),
    )

    parser.add_argument(
        "--verify-latest",
        default=True,
        help=(
            "Set this parameter to true to verify regression against latest released version."
            "Default behavior is to test regression for oldest released version of dependent packages"
        ),
    )

    parser.add_argument(
        "--temp-dir",
        help=(
            "Temporary path to clone github repo of azure-sdk-for-python to run tests. Any changes in this path will be overwritten"
        ),
    )

    args = parser.parse_args()
    run_main(args)