from tls import TLSTester
from eap import EapWithTls
from ike import IKEv2WithEap, IKEv2Exception, IKEv2UnsupportedByServer, IKEv2NoEapPayloadException

import json
import traceback

def main():
    host =  "vpn.kubus-it.de"
    port = int( 500)

    identity = "michael.braun@kubus-it.de"
    sni="kubus-it.de"
    
    ret = scan(host, port, identity, sni, lambda msg: print(msg))

    print(json.dumps(ret))

def scan(host, port, identity, sni, logger):
    logger('Scanning IKEv2')

    # 1. detect diffie-hellmann   
    supportedDhAlg = []
    for dhAlg in IKEv2WithEap.supportedDhAlg():
        if testProto(host = host, port = port, dhAlg = [ dhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange, logger = logger):
            supportedDhAlg.append(dhAlg)
    if len(supportedDhAlg) == 0:
        raise Exception("No supported DH algorithm found")
    selectedDhAlg = supportedDhAlg[0]

    # 2. detect cryto alg
    supportedCryptoAlg = []
    for cryptoAlg in IKEv2WithEap.cryptoAlgRange:
        if testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = [ cryptoAlg ], prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange, logger = logger):
            supportedCryptoAlg.append(cryptoAlg)
    if len(supportedCryptoAlg) == 0:
        raise Exception("No supported crypto algorithm found")

    # 3. detect prf alg
    supportedPrfAlg = []
    for prfAlg in IKEv2WithEap.prfAlgRange:
        if testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = [ prfAlg ], authAlg = IKEv2WithEap.authAlgRange, logger = logger):
            supportedPrfAlg.append(prfAlg)
    if len(supportedPrfAlg) == 0:
        raise Exception("No supported prf algorithm found")

    # 4. detect auth alg
    supportedAuthAlg = []
    for authAlg in IKEv2WithEap.authAlgRange:
        if testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = [ authAlg ], logger = logger):
            supportedAuthAlg.append(authAlg)
    if len(supportedAuthAlg) == 0:
        raise Exception("No supported auth algorithm found")
    
    supportedCryptoAlgTxt = [ IKEv2WithEap.algToText(1, algId) for algId in supportedCryptoAlg ]
    supportedPrfAlgTxt = [ IKEv2WithEap.algToText(2, algId) for algId in supportedPrfAlg ]
    supportedAuthAlgTxt = [ IKEv2WithEap.algToText(3, algId) for algId in supportedAuthAlg ]
    supportedDhAlgTxt = [ IKEv2WithEap.algToText(4, algId) for algId in supportedDhAlg ]
    
    logger(f"supported dh alg: {supportedDhAlgTxt}")
    logger(f"supported prf alg: {supportedPrfAlgTxt}")
    logger(f"supported auth alg: {supportedAuthAlgTxt}")
    logger(f"supported crypto alg: {supportedCryptoAlgTxt}")

    # 5. detect EAP-TLS version
    supportedTlsVersion = None
    supportedCryptoAlg = [ algId for algId in supportedCryptoAlg if algId in IKEv2WithEap.supportedCryptoAlg() ]
    if len(supportedCryptoAlg) == 0:
        logger("cannot test EAP - no supported crypto cipher found")
    else:
        supportedTlsVersion = []
        for tlsProto in TLSTester.supportedProtos():
            ret = testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = supportedCryptoAlg, prfAlg = supportedPrfAlg, authAlg = supportedAuthAlg, identity = identity, servername = sni, tlsVersion = tlsProto, logger = logger)
            if ret and "eapTlsVersion" in ret:
                supportedTlsVersion.append(ret["eapTlsVersion"])

    logger(f"supported tls version: {supportedTlsVersion}")

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


def testProto(host, port, dhAlg, cryptoAlg, prfAlg, authAlg, identity = None, servername = None, tlsVersion = None, logger = lambda msg: print(msg)):

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
                logger(f"IKEv2 AUTH Error: {ex}")
                logger(str(ex) + "\n" + "\n".join(traceback.format_exception(ex)))
                pass
            result.update({
                "eapTlsVersion": tlsHandler.selectedVersion,
                "eapTlsProto": tlsHandler.selectedProto
            })
    except IKEv2UnsupportedByServer:
        return False
    except IKEv2Exception as ex:
        logger(f"IKEv2 INIT Error: {ex}")
        logger(str(ex) + "\n" + "\n".join(traceback.format_exception(ex)))
        return False

    del(ikeHandler)

    return result
