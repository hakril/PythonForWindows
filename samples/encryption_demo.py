import argparse
import windows.crypto as crypto
from windows import winproxy
from windows.generated_def import *

import windows.crypto.generation as gencrypt

# http://stackoverflow.com/questions/1461272/basic-questions-on-microsoft-cryptoapi

def crypt(src, dst, certs, **kwargs):
    """Encrypt the content of 'src' file with the certifacts in 'certs' into 'dst'"""
    # Open every certificates in the certs list
    certlist = [crypto.CertificateContext.from_file(x) for x in certs]
    # Encrypt the content of 'src' with all the public keys(certs)
    res = crypto.encrypt(certlist, src.read())
    print("Encryption done. Result:")
    print(repr(res))
    # Write the result in 'dst'
    dst.write(res)
    dst.close()
    src.close()

def decrypt(src, pfxfile, password, **kwargs):
    """Decrypt the content of 'src' with the private key in 'pfxfile'. the 'pfxfile' is open using the 'password'"""
    # Open the 'pfx' with the given password
    pfx = crypto.import_pfx(pfxfile.read(), password)
    # Decrypt the content of the file
    decrypted = crypto.decrypt(pfx, src.read())
    print(u"Result = <{0}>".format(decrypted))
    return decrypted

PFW_TMP_KEY_CONTAINER = "PythonForWindowsTMPContainer"

def genkeys(common_name, pfxpassword, outname, **kwargs):
    """Generate a SHA256/RSA key pair. A self-signed certificate with 'common_name' is stored as 'outname'.cer.
    The private key is stored in 'outname'.pfx protected with 'pfxpassword'"""
    cert_store = crypto.EHCERTSTORE.new_in_memory()
    # Create a TMP context that will hold our newly generated key-pair
    with crypto.CryptContext(PFW_TMP_KEY_CONTAINER, None, PROV_RSA_FULL, 0, retrycreate=True) as ctx:
        key = HCRYPTKEY()
        # Generate a key-pair that is exportable
        winproxy.CryptGenKey(ctx, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, key)
        # It does NOT destroy the key-pair from the container,
        # It only release the key handle
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379918(v=vs.85).aspx
        winproxy.CryptDestroyKey(key)

    # Descrption of the key-container that will be used to generate the certificate
    KeyProvInfo = CRYPT_KEY_PROV_INFO()
    KeyProvInfo.pwszContainerName = PFW_TMP_KEY_CONTAINER
    KeyProvInfo.pwszProvName = None
    KeyProvInfo.dwProvType = PROV_RSA_FULL
    KeyProvInfo.dwFlags = 0
    KeyProvInfo.cProvParam = 0
    KeyProvInfo.rgProvParam = None
    #KeyProvInfo.dwKeySpec = AT_SIGNATURE
    KeyProvInfo.dwKeySpec = AT_KEYEXCHANGE

    crypt_algo = CRYPT_ALGORITHM_IDENTIFIER()
    crypt_algo.pszObjId = szOID_RSA_SHA256RSA

    certif_name = "CN={0}".format(common_name)
    # Generate a self-signed certificate based on the given key-container and signature algorithme
    certif = gencrypt.generate_selfsigned_certificate(certif_name, key_info=KeyProvInfo, signature_algo=crypt_algo)
    # Add the newly created certificate to our TMP cert-store
    cert_store.add_certificate(certif)
    # Generate a pfx from the TMP cert-store
    pfx = gencrypt.generate_pfx(cert_store, pfxpassword)
    if outname is None:
        outname = common_name.lower()

    # Dump the certif (public key) and pfx (public + private keys)
    with open(outname + ".cer", "wb") as f:
        # The encoded certif only contains the public key
        f.write(certif.encoded)
    with open(outname + ".pfx", "wb") as f:
        f.write(pfx)
    print(certif)
    # Destroy the TMP key container
    prov = HCRYPTPROV()
    winproxy.CryptAcquireContextW(prov, PFW_TMP_KEY_CONTAINER, None, PROV_RSA_FULL, CRYPT_DELETEKEYSET)

parser = argparse.ArgumentParser(prog='PROG')
subparsers = parser.add_subparsers(description='valid subcommands',)

cryptparse = subparsers.add_parser('crypt')
cryptparse.set_defaults(func=crypt)

cryptparse.add_argument('src', type=argparse.FileType('rb'), help='File to encrypt')
cryptparse.add_argument('dst', type=argparse.FileType('wb'), help='The encrypted file')
cryptparse.add_argument('certs', type=str, nargs='+',
                    help='List of certfile used to encrypt the src')

decryptparse = subparsers.add_parser('decrypt')
decryptparse.set_defaults(func=decrypt)
decryptparse.add_argument('src', type=argparse.FileType('rb'), help='File to decrypt')
decryptparse.add_argument('pfxfile', type=argparse.FileType('rb'), help='PFX file to use')
decryptparse.add_argument('password', help='Password of the PFX')

genkeysparse = subparsers.add_parser('genkey')
genkeysparse.set_defaults(func=genkeys)
genkeysparse.add_argument('common_name', nargs='?', metavar='CommonName', default='DEFAULT', help='the common name of the certificate')
genkeysparse.add_argument('outname', nargs='?',help='The filename base for the generated files')
genkeysparse.add_argument('--pfxpassword', nargs='?', help='Password to protect the PFX')

res = parser.parse_args()
res.func(**res.__dict__)