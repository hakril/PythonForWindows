import windows.crypto

windowscert = """-----BEGIN CERTIFICATE-----
MIIFBDCCA+ygAwIBAgITMwAAAQZuwyXEMckYDgAAAAABBjANBgkqhkiG9w0BAQsF
ADCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEuMCwGA1UE
AxMlTWljcm9zb2Z0IFdpbmRvd3MgUHJvZHVjdGlvbiBQQ0EgMjAxMTAeFw0xNjEw
MTEyMDM5MzFaFw0xODAxMTEyMDM5MzFaMHAxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
ZnQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEU1pY3Jvc29mdCBXaW5kb3dzMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyWcaCYghNInk3ecpyu2uZ7LCV9QS
7GWYr41ufTkcL66ewHxlAoWjmkKG6W2Bp9BYYQok10iDeDGACE9Vjr6m4Jdh+YuN
RLxMnHC8JTGzk96CzmdBPAuUWdAcHNmTkIWQF6AXzsbBWsekQejvDBygAOCuIYh4
sBgNa5cjTxQc7Iyp9c7RxBmThV5BNFTOnSN6D9N8zU+ENgIZuyHxGvqzRdrhU4G4
Cg/h1CkI4TgeZQZCeUNPnWV6DMuvPCiqGEia5phOJZyENKND0Sx6eQZrYnuz1gMn
YaEnO+ggegtt4pWpqg8Ch0jNrkL1fb3Kzz7E34/K9dcTgaOymfF6qUKabQIDAQAB
o4IBgDCCAXwwHwYDVR0lBBgwFgYKKwYBBAGCNwoDBgYIKwYBBQUHAwMwHQYDVR0O
BBYEFBEciVg/vsVmKtr/hmHt7KM6g8lSMFIGA1UdEQRLMEmkRzBFMQ0wCwYDVQQL
EwRNT1BSMTQwMgYDVQQFEysyMjk4NzkrMTQ3NDQ5YmUtMTVhOC00ZWJhLTkzZjMt
ZDExMGE1YzQ1NTUyMB8GA1UdIwQYMBaAFKkpAjmOFsSXeM2Q+Z5PmuF8Va9TMFQG
A1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
Y3JsL01pY1dpblByb1BDQTIwMTFfMjAxMS0xMC0xOS5jcmwwYQYIKwYBBQUHAQEE
VTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
L2NlcnRzL01pY1dpblByb1BDQTIwMTFfMjAxMS0xMC0xOS5jcnQwDAYDVR0TAQH/
BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAvYC1iawgKoxXAotQXaN0lj1J5VX01/un
7JybZF4sPMG4acoFT85Ao5U6TK5ATPB7yPUulAivp8908DwTGqN+Ju6iH+UkvAb+
a/WcHVEMxQXK5eOFNE6yekUArBGbMNWlTFrpwklmVTnL9R+4aApTEe6ITT1KLDio
5uFw98n5Sqgh+In073czyiTG7MVhBexbOfhgnciXoufeyhwy1pYgjouSqSQZs4bj
cUwQTwGlS2Gd5a+3nblhjn+QhSszIo1K5n1udLPFWtn29BuGlSrtTXPv5OCfNtLO
l2ec6CyjDQc6HcQBNCsbJVq6qGtQbYNE+ih+KhIU4tO5jf25xthf2g==
-----END CERTIFICATE-----"""


raw_cert = ("".join(windowscert.split("\n")[1:-1])).decode('base64')
cert = windows.crypto.CertificateContext.from_buffer(raw_cert)

print("Analysing certificate: {0}".format(cert))
print("* name: <{0}>".format(cert.name))
print("* issuer: <{0}>".format(cert.issuer))
print("* raw_serial: <{0}>".format(cert.raw_serial))
print("* serial: <{0}>".format(cert.serial))
print("* encoded start: <{0!r}>".format(cert.encoded[:20]))

print ""
chains = cert.chains
print("This certificate has {0} certificate chain".format(len(chains)))
for i, chain in enumerate(chains):
    print("Chain {0}:".format(i))
    for ccert in chain:

        print("  {0}:".format(ccert))
        print("    * issuer: <{0}>".format(ccert.issuer))

print ""
cert_to_verif = ccert
print("Looking for <{0}> in trusted certificates".format(cert_to_verif.name))
root_store = windows.crypto.EHCERTSTORE.from_system_store("Root")
# This is not the correct way verify the validity of a certificate chain.
# I would say that if the goal is to verify the signature of the certificate: use wintrust.
# (or maybe CertVerifyCertificateChainPolicy : https://msdn.microsoft.com/en-us/library/windows/desktop/aa377163(v=vs.85).aspx)
matchs = [c for c in root_store.certs if c == cert_to_verif]
print("matches = {0}".format(matchs))
if matchs:
    print("Found it !")
else:
    print("Not found :(")