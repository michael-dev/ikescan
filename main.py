from tls import TLSTester
from eap import EapWithTls
from ike import IKEv2WithEap, IKEv2Exception, IKEv2UnsupportedByServer, IKEv2NoEapPayloadException, IKEv2NoAnswerException

import asyncio
import json
import traceback

def main():
    host =  "vpn.kubus-it.de"
    port = int( 500)

    identity = "michael.braun@kubus-it.de"
    sni="kubus-it.de"
    
    ret = asyncio.run(scan(host, port, identity, sni, lambda msg: print(msg)), debug=False)

    print(json.dumps(ret))

async def scan(host, port, identity, sni, logger):
    logger('Scanning IKEv2')

    # 1. detect diffie-hellmann   
    taskList = []
    for dhAlg in IKEv2WithEap.supportedDhAlg():
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ dhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange, logger = logger)))
    supportedDhAlg = set()
    for f in asyncio.as_completed(taskList):
        ret = await f
        if ret:
            supportedDhAlg.add(ret["chosenDhAlg"])
    if len(supportedDhAlg) == 0:
        raise Exception("No supported DH algorithm found")
    selectedDhAlg = list(supportedDhAlg)[0]
    supportedDhAlgTxt = [ IKEv2WithEap.algToText(4, algId) for algId in supportedDhAlg ]
    logger(f"supported dh alg: {supportedDhAlgTxt}")

    # 2. detect cryto / prf / auth alg
    taskList = []
    for cryptoAlg in IKEv2WithEap.cryptoAlgRange:
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = [ cryptoAlg ], prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange, logger = logger)))
    for prfAlg in IKEv2WithEap.prfAlgRange:
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = [ prfAlg ], authAlg = IKEv2WithEap.authAlgRange, logger = logger)))
    for authAlg in IKEv2WithEap.authAlgRange:
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = [ authAlg ], logger = logger)))

    supportedCryptoAlg = set()
    supportedPrfAlg = set()
    supportedAuthAlg = set()
    for f in asyncio.as_completed(taskList):
        ret = await f
        if ret and ret["chosenCryptoAlg"]:
            supportedCryptoAlg.add((ret["chosenCryptoAlg"], ret["chosenCryptoKeyLength"]))
        if ret and ret["chosenPrfAlg"]:
            supportedPrfAlg.add(ret["chosenPrfAlg"])
        if ret and ret["chosenAuthAlg"]:
            supportedAuthAlg.add(ret["chosenAuthAlg"])
    if len(supportedCryptoAlg) == 0:
        raise Exception("No supported crypto algorithm found")
    if len(supportedPrfAlg) == 0:
        raise Exception("No supported prf algorithm found")
    if len(supportedAuthAlg) == 0:
        raise Exception("No supported auth algorithm found")
    supportedCryptoAlgTxt = [ IKEv2WithEap.algToText(1, algId[0]) + (f" {algId[1]}" if algId[1] is not None else "") for algId in supportedCryptoAlg ]
    supportedPrfAlgTxt = [ IKEv2WithEap.algToText(2, algId) for algId in supportedPrfAlg ]
    supportedAuthAlgTxt = [ IKEv2WithEap.algToText(3, algId) for algId in supportedAuthAlg ]
    logger(f"supported crypto alg: {supportedCryptoAlgTxt}")
    logger(f"supported prf alg: {supportedPrfAlgTxt}")
    logger(f"supported auth alg: {supportedAuthAlgTxt}")

    # 5. detect EAP-TLS version
    supportedTlsVersion = None
    supportedCryptoAlgForIkeAuth = [ algId[0] for algId in supportedCryptoAlg if algId[0] in IKEv2WithEap.supportedCryptoAlg() ]
    if len(supportedCryptoAlgForIkeAuth) == 0:
        logger("cannot test EAP - no supported crypto cipher found")
    else:
        logger(f"testing EAP-TLS with identity={identity} and servername={sni} and tlsVersion={TLSTester.supportedProtos()}")
        taskList = []
        for tlsProto in TLSTester.supportedProtos():
            taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = supportedCryptoAlgForIkeAuth, prfAlg = supportedPrfAlg, authAlg = supportedAuthAlg, identity = identity, servername = sni, tlsVersion = tlsProto, logger = logger)))
        supportedTlsVersion = set()
        for f in asyncio.as_completed(taskList):
            ret = await f
            if ret and "eapTlsVersion" in ret and ret["eapTlsVersion"]:
                supportedTlsVersion.add(ret["eapTlsVersion"])

    logger(f"supported tls version: {list(supportedTlsVersion)}")

    ret = {
        "host": host,
        "port": port,
        "supported dh alg": supportedDhAlgTxt,
        "supported prf alg": supportedPrfAlgTxt,
        "supported auth alg": supportedAuthAlgTxt,
        "supported crypto alg": supportedCryptoAlgTxt,
        "supported tls version": list(supportedTlsVersion),
    }
    
    
    return ret


async def testProto(host, port, dhAlg, cryptoAlg, prfAlg, authAlg, identity = None, servername = None, tlsVersion = None, logger = lambda msg: print(msg)):

    if identity is not None:
        tlsHandler = TLSTester(proto=tlsVersion,servername=servername)
        eapHandler = EapWithTls(tlsHandler, identity)
    else:
        eapHandler = None

    ikeHandler = IKEv2WithEap(eapHandler, host, port, cryptoAlg, prfAlg, authAlg, dhAlg, identity, None, logger = logger) # optionally pass debugRandom

    try:
        await ikeHandler.doSaInit()
        result = {
            "chosenCryptoAlg": ikeHandler.chosenCryptoAlg,
            "chosenCryptoKeyLength": ikeHandler.chosenCryptoKeyLength,
            "chosenAuthAlg": ikeHandler.chosenAuthAlg,
            "chosenPrfAlg": ikeHandler.chosenPrfAlg,
            "chosenDhAlg": ikeHandler.chosenDhAlg,
        }

        if eapHandler is not None:
            try:
                await ikeHandler.doSaAuth()
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
    except IKEv2NoAnswerException as ex:
        logger(f"IKEv2 INIT Error: {ex}")
        logger(str(ex) + "\n" + "\n".join(traceback.format_exception(ex)))
        raise ex
    except IKEv2UnsupportedByServer:
        return False
    except IKEv2Exception as ex:
        logger(f"IKEv2 INIT Error: {ex}")
        logger(str(ex) + "\n" + "\n".join(traceback.format_exception(ex)))
        return False
    finally:
        del(ikeHandler)

    return result

if __name__ == '__main__':
    main()
