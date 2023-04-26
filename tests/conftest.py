import pytest

API_PREFIX = "/api/v1"


def pytest_addoption(parser):
    parser.addoption(
        "--server",
        action="store",
        default="local",
        help="""Which server are we testing? Possible values:\n cloud\n local""",
    )
    parser.addoption(
        "--user",
        action="store",
        default="john",
        help="""User ID of the user to be used during the tests""",
    )
    parser.addoption(
        "--password",
        action="store",
        default="qwerty",
        help="""Password of the user for the tests""",
    )
    parser.addoption(
        "--otp",
        action="store",
        default="123456",
        help="""What is the OTP code the server will generate""",
    )
    parser.addoption(
        "--tenant",
        action="store",
        default="",
        help="""Tenant ID (in case of multi-tenant setup)""",
    )


@pytest.fixture
def auth_bearer(token: str):
    return {"Authorization": "Bearer " + token}


SERVER_URL = {
    "cloud": "https://webtrit-adapter-pckcvcauxq-ey.a.run.app",
    "local": "http://127.0.0.1:8000",
    "custom": "add your own URL",
}


@pytest.fixture
def api_url(request):
    global SERVER_URL
    got_option = str(request.config.getoption("--server"))

    server_option = got_option if got_option else "local"

    if server_option in SERVER_URL:
        # predefined options
        return SERVER_URL[server_option]

    if server_option.lower().startswith("http"):
        # then we assume the user provided the actual URL in the param
        return server_option
    # hm, what to do?
    raise ValueError(
        f"Unknown --server option {got_option}."
        + " Provide a real URL (e.g. 'https://myhost.com:8000') or "
        + "'local' to test http://127.0.0.1:8000/'"
    )


@pytest.fixture
def system_info_path():
    global API_PREFIX
    return API_PREFIX + "/system-info"


@pytest.fixture
def login_path():
    global API_PREFIX
    return API_PREFIX + "/session"


@pytest.fixture
def otp_create_path():
    global API_PREFIX
    return API_PREFIX + "/session/otp-create"


@pytest.fixture
def otp_verify_path():
    global API_PREFIX
    return API_PREFIX + "/session/otp-verify"


@pytest.fixture
def userinfo_path():
    global API_PREFIX
    return API_PREFIX + "/user"


@pytest.fixture
def extensions_path():
    global API_PREFIX
    return API_PREFIX + "/user/contacts"


@pytest.fixture
def call_history_path():
    global API_PREFIX
    return API_PREFIX + "/user/history"


@pytest.fixture
def username(request):
    got_option = str(request.config.getoption("--user"))
    return got_option


@pytest.fixture
def password(request):
    got_option = str(request.config.getoption("--password"))
    return got_option


@pytest.fixture
def tenant_id(request):
    got_option = str(request.config.getoption("--tenant"))
    return got_option

# to make the auto-test work, we have to pre-configure the same
# code in the test suite and on the sever. By default the OTP
# is 123456, but you can change it via --otp <your-code> command
# line parameter when running the tests.
# Run the FastAPI server setting env var
# PERMANENT_OTP_CODE = "your-otp-code"
@pytest.fixture
def otp_code(request):
    got_option = str(request.config.getoption("--otp"))
    return got_option
