import pytest

import windows.crypto
import windows.generated_def as gdef

from pfwtest import *

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')

TEST_CERT = """
MIIBwTCCASqgAwIBAgIQG46Uyws+67ZBOfPJCbFrRjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQD
ExRQeXRob25Gb3JXaW5kb3dzVGVzdDAeFw0xNzA0MTIxNDM5MjNaFw0xODA0MTIyMDM5MjNaMB8x
HTAbBgNVBAMTFFB5dGhvbkZvcldpbmRvd3NUZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQCRHwC/sRfXh5pc4poc85aidrudbPdya+0OeonQlf1JQ1ekf7KSfADV5FLkSQu2BzgBK9DIWTGX
XknBJIzZF03UZsVg5D67V2mnSClXucc0cGFcK4pDDt0tHeabA2GPinVe7Z6qDT4ZxPR8lKaXDdV2
Pg2hTdcGSpqaltHxph7G/QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBACcQFdOlVjYICOIyAXowQaEN
qcLpN1iWoL9UijNhTY37+U5+ycFT8QksT3Xmh9lEIqXMh121uViy2P/3p+Ek31AN9bB+BhWIM6PQ
gy+ApYDdSwTtWFARSrMqk7rRHUveYEfMw72yaOWDxCzcopEuADKrrYEute4CzZuXF9PbbgK6"""

## Cert info:
#  Name: PythonForWindowsTest
#  Serial: '1b 8e 94 cb 0b 3e eb b6 41 39 f3 c9 09 b1 6b 46'

TEST_PFX_PASSWORD = "TestPassword"

TEST_PFX = """
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
"""

@pytest.fixture()
def rawcert():
    return TEST_CERT.decode("base64")


@pytest.fixture()
def rawpfx():
    return TEST_PFX.decode("base64")


def test_certificate(rawcert):
    cert = windows.crypto.CertificateContext.from_buffer(rawcert)
    assert cert.serial == '1b 8e 94 cb 0b 3e eb b6 41 39 f3 c9 09 b1 6b 46'
    assert cert.name == 'PythonForWindowsTest'
    cert.chains # TODO: craft a certificate with a chain for test purpose


def test_pfx(rawcert, rawpfx):
    pfx = windows.crypto.import_pfx(rawpfx, TEST_PFX_PASSWORD)
    orig_cert = windows.crypto.CertificateContext.from_buffer(rawcert)
    certs = pfx.certs
    assert len(certs) == 1
    # Test cert comparaison
    assert certs[0] == orig_cert


def test_open_pfx_bad_password(rawpfx):
    with pytest.raises(WindowsError) as ar:
        pfx = windows.crypto.import_pfx(rawpfx, "BadPassword")


def test_encrypt_decrypt(rawcert, rawpfx):
    message_to_encrypt = "Testing message \xff\x01"
    cert = windows.crypto.CertificateContext.from_buffer(rawcert)
    # encrypt should accept a cert or iterable of cert
    res = windows.crypto.encrypt(cert, message_to_encrypt)
    res2 = windows.crypto.encrypt([cert], message_to_encrypt)
    del cert
    assert message_to_encrypt not in res

    # Open pfx and decrypt
    pfx = windows.crypto.import_pfx(rawpfx, TEST_PFX_PASSWORD)
    decrypt = windows.crypto.decrypt(pfx, res)
    decrypt2 = windows.crypto.decrypt(pfx, res2)

    assert message_to_encrypt == decrypt
    assert decrypt == decrypt2

def test_crypt_obj():
    path = r"C:\windows\system32\kernel32.dll"
    x = windows.crypto.CryptObject(path)
    x.crypt_msg.certs
    x.crypt_msg.signers
    x.signers_and_certs
    # TODO: Need some better ideas

def test_certificate_from_store():
    return windows.crypto.EHCERTSTORE.from_system_store("Root")


