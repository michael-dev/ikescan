from tls import TLSTester
from eap import EapWithTls
from ike import IKEv2WithEap, IKEv2Exception, IKEv2UnsupportedByServer, IKEv2NoEapPayloadException

import json
import traceback

def main():
    print('Scanning IKEv2')

    host =  "vpn.kubus-it.de"
    port = int( 500)

    identity = "michael.braun@kubus-it.de"
    sni="kubus-it.de"
    
    ret = scan(host, port, identity, sni)

    print(json.dumps(ret))

def scan(host, port, identity, sni):
    # 1. detect diffie-hellmann   
    supportedDhAlg = []
    for dhAlg in IKEv2WithEap.supportedDhAlg():
        if testProto(host = host, port = port, dhAlg = [ dhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange):
            supportedDhAlg.append(dhAlg)
    if len(supportedDhAlg) == 0:
        raise Exception("No supported DH algorithm found")
    selectedDhAlg = supportedDhAlg[0]

    # 2. detect cryto alg
    supportedCryptoAlg = []
    for cryptoAlg in IKEv2WithEap.cryptoAlgRange:
        if testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = [ cryptoAlg ], prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange):
            supportedCryptoAlg.append(cryptoAlg)
    if len(supportedCryptoAlg) == 0:
        raise Exception("No supported crypto algorithm found")

    # 3. detect prf alg
    supportedPrfAlg = []
    for prfAlg in IKEv2WithEap.prfAlgRange:
        if testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = [ prfAlg ], authAlg = IKEv2WithEap.authAlgRange):
            supportedPrfAlg.append(prfAlg)
    if len(supportedPrfAlg) == 0:
        raise Exception("No supported prf algorithm found")

    # 4. detect auth alg
    supportedAuthAlg = []
    for authAlg in IKEv2WithEap.authAlgRange:
        if testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = [ authAlg ]):
            supportedAuthAlg.append(authAlg)
    if len(supportedAuthAlg) == 0:
        raise Exception("No supported auth algorithm found")
    
    supportedCryptoAlgTxt = [ IKEv2WithEap.algToText(1, algId) for algId in supportedCryptoAlg ]
    supportedPrfAlgTxt = [ IKEv2WithEap.algToText(2, algId) for algId in supportedPrfAlg ]
    supportedAuthAlgTxt = [ IKEv2WithEap.algToText(3, algId) for algId in supportedAuthAlg ]
    supportedDhAlgTxt = [ IKEv2WithEap.algToText(4, algId) for algId in supportedDhAlg ]
    
    print(f"supported dh alg: {supportedDhAlgTxt}")
    print(f"supported prf alg: {supportedPrfAlgTxt}")
    print(f"supported auth alg: {supportedAuthAlgTxt}")
    print(f"supported crypto alg: {supportedCryptoAlgTxt}")

    # 5. detect EAP-TLS version
    supportedTlsVersion = None
    supportedCryptoAlg = [ algId for algId in supportedCryptoAlg if algId in IKEv2WithEap.supportedCryptoAlg() ]
    if len(supportedCryptoAlg) == 0:
        print("cannot test EAP - no supported crypto cipher found")
    else:
        supportedTlsVersion = []
        for tlsProto in TLSTester.supportedProtos():
            ret = testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = supportedCryptoAlg, prfAlg = supportedPrfAlg, authAlg = supportedAuthAlg, identity = identity, servername = sni, tlsVersion = tlsProto)
            if ret and ret["eapTlsVersion"]:
                supportedTlsVersion.append(ret["eapTlsVersion"])

    print(f"supported tls version: {supportedTlsVersion}")

    ret = {
        "host": host,
        "port": port,
        "supported dh alg": supportedDhAlgTxt,
        "supported prf alg": supportedPrfAlgTxt,
        "supported auth alg": supportedAuthAlgTxt,
        "supported crypto alg": supportedCryptoAlgTxt,
        "supported tls version": supportedTlsVersion,
    }
    
    
    return ret


def testProto(host, port, dhAlg, cryptoAlg, prfAlg, authAlg, identity = None, servername = None, tlsVersion = None):

    if identity is not None:
        tlsHandler = TLSTester(proto=tlsVersion,servername=servername)
        eapHandler = EapWithTls(tlsHandler, identity)
    else:
        eapHandler = None

    ikeHandler = IKEv2WithEap(eapHandler, host, port, cryptoAlg, prfAlg, authAlg, dhAlg, identity, None) # optionally pass debugRandom

    try:
        ikeHandler.doSaInit()
        result = {
            "chosenCryptoAlg": ikeHandler.chosenCryptoAlg,
            "chosenCryptoKeyLength": ikeHandler.chosenCryptoKeyLength,
            "chosenAuthAlg": ikeHandler.chosenAuthAlg,
            "chosenPrfAlg": ikeHandler.chosenPrfAlg,
            "chosenDhAlg": ikeHandler.chosenDhAlg,
        }

        if eapHandler is not None:
            try:
                ikeHandler.doSaAuth()
            except IKEv2NoEapPayloadException:
                pass
            except IKEv2Exception as ex:
                print(f"IKEv2 AUTH Error: {ex}")
                print(str(ex) + "\n" + "\n".join(traceback.format_exception(ex)))
                pass
            result.update({
                "eapTlsVersion": tlsHandler.selectedVersion,
                "eapTlsProto": tlsHandler.selectedProto
            })
    except IKEv2UnsupportedByServer:
        return False
    except IKEv2Exception as ex:
        print(f"IKEv2 INIT Error: {ex}")
        print(str(ex) + "\n" + "\n".join(traceback.format_exception(ex)))
        return False

    return result

def int_arr(s):
    return [int(v) for v in str(s).split(",")]

debugRandom = {
    "myspi": "4e4b4577536e5242",
    "nonce" : "f9738cc1394e1b7a54e92824cdf7c8cefb7d3ac135d9fde76d9f254e7e85e0c703e5e68f1f3ab949ac1c97ebfe7da8de68f1560071b86606426ca2a0370d711a5a841a088abf94dbfd11b14b1059ec06e3e94f1f25bec7be3b02f24c82c88479b930b0e7c95b54462412aefb28f0d1ebd77efc07d2baee7099e7db1b1ff507a56ef7a1853329a4a436c80477d9969e0686087caf3b826d51d7a4cab2d4007b58221bb3ced19913f1b94fb1d1d7f81e8f990e0a9d678d36d34de44021cd51b047b9f3c9010100ad9808b702ca1e1a0165c9786d4d27dcefdd3ed8416f2f35ac6e1ee85f4270db47027b9e25589b3aa2e3",
    "dh": """-----BEGIN DH PARAMETERS-----
MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR
Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL
/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC
-----END DH PARAMETERS-----""",
    "dhkey": """-----BEGIN PRIVATE KEY-----
MIIBIQIBADCBlQYJKoZIhvcNAQMBMIGHAoGBAP//////////yQ/aoiFowjTExmKL
gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt
bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR
7OZTgf//////////AgECBIGDAoGAd1Uw0BwtYDN5IrXCRgCTuTzPtHqbx6Fam2U4
OuXn/4fW7ZfD7w2XJkQkTBTtoAvnhubwtBYuJtnc7hhqsWg0QumQV7i4sFI6f1Sx
cbq32MrP03/XcxH2JNq7ugmpnYUOxsitLKmOUivIDXyZKCaWXLD0tfw4iioQvZFC
3shxHyo=
-----END PRIVATE KEY-----""",
    "dhGroup": 2,
    "dhKe": "b0e8ca924fda4bd818a7efb1a98fef3afc95e7911810e9a3d20fc8214915bfd46069014d34d0ef9e31ed231039114ac673335a6af93d7ffbcdbde2d168ed5757a603b321b547bc9d90b9a4d9dd95727d65601afc287ef4e3375dc7285c28f871af6e32ccec9257bd2151e9428e412745dea351cf6b34c531cfef254bd3ae63fd",
    "sending1": "4e4b4577536e524200000000000000002120220800000000000001c42200002c0000002801010004030000080100000c0300000803000002030000080200000200000008040000022800008800020000b0e8ca924fda4bd818a7efb1a98fef3afc95e7911810e9a3d20fc8214915bfd46069014d34d0ef9e31ed231039114ac673335a6af93d7ffbcdbde2d168ed5757a603b321b547bc9d90b9a4d9dd95727d65601afc287ef4e3375dc7285c28f871af6e32ccec9257bd2151e9428e412745dea351cf6b34c531cfef254bd3ae63fd000000f4f9738cc1394e1b7a54e92824cdf7c8cefb7d3ac135d9fde76d9f254e7e85e0c703e5e68f1f3ab949ac1c97ebfe7da8de68f1560071b86606426ca2a0370d711a5a841a088abf94dbfd11b14b1059ec06e3e94f1f25bec7be3b02f24c82c88479b930b0e7c95b54462412aefb28f0d1ebd77efc07d2baee7099e7db1b1ff507a56ef7a1853329a4a436c80477d9969e0686087caf3b826d51d7a4cab2d4007b58221bb3ced19913f1b94fb1d1d7f81e8f990e0a9d678d36d34de44021cd51b047b9f3c9010100ad9808b702ca1e1a0165c9786d4d27dcefdd3ed8416f2f35ac6e1ee85f4270db47027b9e25589b3aa2e3",
    "received1": "4e4b4577536e5242bfa6452e02986e7521202220000000000000016c220000300000002c010100040300000c0100000c800e00800300000803000002030000080200000200000008040000022800008800020000862b25b4471787c60c023de65a1b7cc57e159b9fdd23ba4e423cbf63012213295d1054966c55aa0ee5ede1a1a181a6c36dcd6eeda2a8b63f9969c07ece851b35d6160b42f0f3be2ee268b267915860f71b6082eb3b79bdc0d8e00c67ca50e2cdc2832a7c9bb968170698ad6239cfb69cb8f419f3508b8f5dc6f1c16293c047e8290000344be5cb680286ba782bc5178be468e13cab388d77f88e86b5f0bd6a921b9a945ef201f46e1d4f43c2bc3d4d99d321a9112900001c00004004a5b832bbf8c24f0837aeee2da2697037f36833ab2b00001c00004005dfba457a05e006612bac9f660cbd778072d224202b0000181e2b516905991c7d7c96fcbfb587e4610000000900000014fb1de3cdf341b7ea16b7e5be0855f120",
    "DH shared secret": "b14e36f06eada1c3559d78bae59cfe66e41ae6f9cb0ea7574fed3fc655675c3bc71fbce640d322d9b516eef1ad93c57f1e5b2db90bc8d839efe1bd55f8810a4467b6ae1e08ff759ebcc387d2c26ea4447554be4e4524ca2e295538febdf5667c4bbb2a146c8d870a832943a41c27c80d41d7f93ba0a15de275a9a3b87cfeecdb",
    "rxNonce1": "4be5cb680286ba782bc5178be468e13cab388d77f88e86b5f0bd6a921b9a945ef201f46e1d4f43c2bc3d4d99d321a911",
    "iv1" : "3969684fa7f98ed0d10301325ca6c59d",
    "sending2": "4e4b4577536e5242bfa6452e02986e752e202308000000010000006c230000503969684fa7f98ed0d10301325ca6c59d022fb8686329c7b8e5cfb5f0f33bf89c3cffef8904e1e98d29ea1707d2a5175ed3418555d1a7745dacdbb46969c60e2a309831d9189202f76da97ad8",
}


main()
