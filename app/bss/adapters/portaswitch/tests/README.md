
# Install dependancies:

python3.11 -m pip install --no-cache-dir --upgrade -r requirements.txt

# For most of the tests it is enough to run:

python3.11 -m pytest --server-url 'http://<server_ip>:<server_port>' --user "<account_id>" --password "<account_password>" \
    --userid '<i_account>' --recordingid '<i_xdr>' -vs .

# For test_08_validate_otp.py:test_validate_otp, there is no automative way, as it depends on token


1. Acquire otp_id from test_07_generate_otp.py test:

python3.11 -m pytest --server-url '<server_ip>:<server_port>' --userid '<i_account>' -vs test_07_generate_otp.py

Test trigger:

python3.11 -m pytest --server-url 'http://127.0.0.1:8080' --userid '1000055' -vs test_07_generate_otp.py

Result example:
test_07_generate_otp.py::TestGenerateOtp::test_unknown_user PASSED
test_07_generate_otp.py::TestGenerateOtp::test_create_otp {'delivery_channel': None,
 'delivery_from': None,
 'otp_id': 'ed2962525e0e11eeb8b50242ac110002262a9dbd0797470faec4cf25dbf1bf73'}
PASSED



2. Manually trigger test_08_validate_otp.py test:

python3.11 -m pytest --server-url '<server_ip>:<server_port>' --otp-id '<otp-id>' --otp-token 'otp-token' -vs test_08_validate_otp.py

Test trigger:

python3.11 -m pytest --server-url 'http://127.0.0.1:8080' --otp-id 'ed2962525e0e11eeb8b50242ac110002262a9dbd0797470faec4cf25dbf1bf73' \
    --otp-token '05248378' -vs test_08_validate_otp.py

Result example:

test_08_validate_otp.py::TestValidateOtp::test_unknown_token PASSED
test_08_validate_otp.py::TestValidateOtp::test_validate_otp {'access_token': 'eyJhbGciOiJSUzI1NiJ9.eyJpc19zdXBlcl91c2VyIjowLCJpYXQiOjE2OTU5MTI4ODUsImxvZ2luIjoiMTIzMDAwIiwiaV9hY2NvdW50IjoxMDAwMDU1LCJpX2VudiI6MywiYXVkIjpbInBvcnRhYmlsbGluZy1hcGkiLCJwb3J0YXNpcC1hcGkiXSwianRpIjoiMTpVMkZzZEdWa1gxODJKb1huWWRJemg1MktnQmcxeHRhNS92VVNWdm5QSU45UmU5dGNQY1JiZ1BiYzdlbWxyVEdQZzV6V1F5TFpiZ0ZzVkZ3R1FjNzVZQT09IiwicmVhbG0iOiJhY2NvdW50cyIsInNjb3BlcyI6IiIsImV4cCI6MTY5NjA4NTY4NX0.w6Ir9b5VdI_Vnw37BwItrMkyLq942JkONEP3byYjUydSOtdtMAgEQ55z2C1OGAq8zWHtd3Al1A6yjnQWALPOPSII4rMbsfL6hDXClccZ9oOH6XClOQs_nOFeoFnCYiCob0mOQ8sN9r2JvBy3v1F8i8bMPd2yksuEWgZmH2hmNE-ghYpyikzYU32M9aSYqbQIi8YETZlTMT-bJ5gLTeHrJNuwDZstM90Dp0o3jaj8H1SdJwYEy6wOSRoCOXDDuflsdu7yahwnPXD487kAqD4NQG-HoWlTDddgfXOs9AzGxK2-GYf4y6HgUmoYT9jxH15NNp14-iXwUEOwFlJmGBPHhw',
 'expires_at': '2023-09-30T14:54:45.590348',
 'refresh_token': '95ca9793a8b3535a9ad80c114499fb10',
 'tenant_id': None,
 'user_id': '1000055'}
PASSED
