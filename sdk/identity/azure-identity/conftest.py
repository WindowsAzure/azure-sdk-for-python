# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import os
import sys

import pytest
from azure.identity._constants import AZURE_CLI_CLIENT_ID, EnvironmentVariables

# Ignore async tests on unsupported platforms
if sys.version_info < (3, 5):
    collect_ignore_glob = ["*_async.py"]

run_manual_tests = False
stdout_captured = True


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "manual: the tested credential requires manual interaction, e.g. InteractiveBrowserCredential"
    )
    config.addinivalue_line("markers", "prints: the tested credential prints to stdout, e.g. DeviceCodeCredential")
    global run_manual_tests, stdout_captured
    run_manual_tests = config.getoption("markexpr") == "manual"
    stdout_captured = config.getoption("capture") != "no"


def pytest_runtest_setup(item):
    # ensure manual tests only run when manual marker is selected with 'pytest -m manual'
    if item.get_closest_marker("manual") and not run_manual_tests:
        pytest.skip("To run manual tests, select 'manual' marker with 'pytest -m manual'")
    elif item.get_closest_marker("prints") and stdout_captured:
        pytest.skip("This test prints to stdout. Run pytest with '-s' to ensure the output is visible.")


@pytest.fixture()
def live_service_principal():  # pylint:disable=inconsistent-return-statements
    """Fixture for live Identity tests. Skips them when environment configuration is incomplete."""

    missing_variables = [
        v
        for v in (
            EnvironmentVariables.AZURE_CLIENT_ID,
            EnvironmentVariables.AZURE_CLIENT_SECRET,
            EnvironmentVariables.AZURE_TENANT_ID,
        )
        if not os.environ.get(v)
    ]
    if any(missing_variables):
        pytest.skip("Environment has no value for {}".format(missing_variables))
    else:
        return {
            "client_id": os.environ[EnvironmentVariables.AZURE_CLIENT_ID],
            "client_secret": os.environ[EnvironmentVariables.AZURE_CLIENT_SECRET],
            "tenant_id": os.environ[EnvironmentVariables.AZURE_TENANT_ID],
        }


@pytest.fixture()
def live_certificate(live_service_principal):  # pylint:disable=inconsistent-return-statements,redefined-outer-name
    """Fixture for live tests needing a certificate.
    Skips them when environment configuration is incomplete.
    """

    pem_content = os.environ.get("PEM_CONTENT")
    if not pem_content:
        pytest.skip("Environment has no value for 'PEM_CONTENT'")
        return

    pem_path = os.path.join(os.path.dirname(__file__), "certificate.pem")
    try:
        with open(pem_path, "w") as pem_file:
            pem_file.write(pem_content)
        return dict(live_service_principal, cert_path=pem_path)
    except IOError as ex:
        pytest.skip("Failed to write file '{}': {}".format(pem_path, ex))


@pytest.fixture()
def live_user_details():
    user_details = {
        "client_id": AZURE_CLI_CLIENT_ID,
        "username": os.environ.get(EnvironmentVariables.AZURE_USERNAME),
        "password": os.environ.get(EnvironmentVariables.AZURE_PASSWORD),
        "tenant": os.environ.get("USER_TENANT"),
    }
    if None in user_details.values():
        pytest.skip("To test username/password authentication, set $AZURE_USERNAME, $AZURE_PASSWORD, $USER_TENANT")
    else:
        return user_details


@pytest.fixture()
def managed_identity_id():
    return os.environ.get("MANAGED_IDENTITY_ID")
