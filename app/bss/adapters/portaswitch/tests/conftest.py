import pytest


API_PREFIX = "/api/v1"


def pytest_addoption(parser):

    print(type(parser))
    parser.addoption(
        "--server-url",
        action="store",
        default="http://127.0.0.1:8080",
        help="""The URL to the Adapter server.""",
    )

    parser.addoption(
        "--user",
        action="store",
        default="john",
        help="""Login of the user to be used during the tests""",
    )

    parser.addoption(
        "--password",
        action="store",
        default="qwerty",
        help="""Password of the user for the tests""",
    )

    parser.addoption(
        "--userid",
        action="store",
        default="john",
        help="""User ID (in case if it differs from the login) of the user to be used during the tests""",
    )

    parser.addoption(
        "--recordingid",
        action="store",
        default="12345",
        help="""The identifier of the call recording.""",
    )
    parser.addoption(
        "--otp-id",
        action="store",
        default="",
        help="""The identifier OTP token.""",
    )
    parser.addoption(
        "--otp-token",
        action="store",
        default="",
        help="""The OTP token acquired via SMS / EMAIL.""",
    )


@pytest.fixture
def api_url(request):
    url = str(request.config.getoption("--server-url"))

    if url.lower().startswith("http"):
        return url

    raise ValueError(
        f"Unknown --server option {url}. Provide a real URL (e.g. 'https://myhost.com:8000')"
    )


@pytest.fixture
def system_info_path():
    return API_PREFIX + "/system-info"


@pytest.fixture
def login_path():
    global API_PREFIX
    return API_PREFIX + "/session"


@pytest.fixture
def username(request):
    return str(request.config.getoption("--user"))


@pytest.fixture
def userid(request):
    got_option = str(request.config.getoption("--userid"))
    return got_option


@pytest.fixture
def password(request):
    return str(request.config.getoption("--password"))


@pytest.fixture
def recording_id(request):
    return str(request.config.getoption("--recordingid"))

@pytest.fixture
def otp_token(request):
    return str(request.config.getoption("--otp-token"))

@pytest.fixture
def otp_id(request):
    return str(request.config.getoption("--otp-id"))


@pytest.fixture
def user_path():
    global API_PREFIX
    return API_PREFIX + "/user"


@pytest.fixture
def contacts_path():
    global API_PREFIX
    return API_PREFIX + "/user/contacts"


@pytest.fixture
def history_path():
    global API_PREFIX
    return API_PREFIX + "/user/history"


@pytest.fixture
def recordings_path():
    global API_PREFIX
    return API_PREFIX + "/user/recordings/"


@pytest.fixture
def otp_create_path():
    global API_PREFIX
    return API_PREFIX + "/session/otp-create"


@pytest.fixture
def otp_verify_path():
    global API_PREFIX
    return API_PREFIX + "/session/otp-verify"
