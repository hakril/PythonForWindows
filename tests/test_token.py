import windows
import windows.generated_def as gdef



def test_token_info():
    token = windows.current_process.token
    assert isinstance(token.computername, basestring)
    assert isinstance(token.username, basestring)
    assert isinstance(token.integrity, (int, long))
    assert isinstance(token.is_elevated, (bool))

def test_lower_integrity(proc32):
    # Lowering the integrity in remote process
    # Because we don't want to mess with the token of our testing process

    proc32.execute_python("import windows")
    # We stock the handle becase lowering the integrity
    # will mess with token retrieval
    proc32.execute_python("token = windows.current_process.token")
    proc32.execute_python("token.integrity = 123")
    # execute_python will raise this in our own process :)
    proc32.execute_python("assert token.integrity == 123")


def test_token_elevation():
    tok = windows.current_process.token
    assert tok.TokenElevation