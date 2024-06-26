from debug import Debug
from eap import EapWithTls
from ike import IKEv2WithEap, IKEv2Exception, IKEv2UnsupportedByServer, IKEv2NoEapPayloadException, IKEv2NoAnswerException
from tls import TLSTester

import aiofiles
import asyncio
import json
import os
import traceback

def main():
    host =  "vpn.kubus-it.de"
    port = int( 500)

    identity = "michael.braun@kubus-it.de"
    sni="vpn.kubus-it.de"
    
    #ret = asyncio.run(scan(host, port, identity, sni, lambda msg: print(msg), restrictDh=[2], restrictCrypto=[12], restrictAuth=[2], restrictPrf=[2], restrictTls=["tls10"]), debug=False)
    ret = asyncio.run(scan(host, port, identity, sni, lambda msg: print(msg)), debug=False)

    print(json.dumps(ret))

async def scan(host, port, identity, sni, logger, restrictDh = None, restrictCrypto = None, restrictPrf = None, restrictAuth = None, restrictTls = None):
    logger('Scanning IKEv2')

    # 1. detect diffie-hellmann   
    taskList = []
    for dhAlg in IKEv2WithEap.supportedDhAlg():
        if restrictDh and dhAlg not in restrictDh:
            continue
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ dhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange, logger = lambda msg, dhAlg=dhAlg: logger(f"DH({dhAlg}): {msg}"))))
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
        if restrictCrypto and cryptoAlg not in restrictCrypto:
            continue
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = [ cryptoAlg ], prfAlg = IKEv2WithEap.prfAlgRange, authAlg = IKEv2WithEap.authAlgRange, logger = lambda msg, cryptoAlg=cryptoAlg: logger(f"Crypto({cryptoAlg}): {msg}"))))
    for prfAlg in IKEv2WithEap.prfAlgRange:
        if restrictPrf and prfAlg not in restrictPrf:
            continue
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = [ prfAlg ], authAlg = IKEv2WithEap.authAlgRange, logger = lambda msg, prfAlg=prfAlg: logger(f"Prf({prfAlg}): {msg}"))))
    for authAlg in IKEv2WithEap.authAlgRange:
        if restrictAuth and authAlg not in restrictAuth:
            continue
        taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = IKEv2WithEap.cryptoAlgRange, prfAlg = IKEv2WithEap.prfAlgRange, authAlg = [ authAlg ], logger = lambda msg, authAlg=authAlg: logger(f"Auth({authAlg}): {msg}"))))

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
        logger(f"testing EAP-TLS with identity={identity} and servername={sni} and tlsVersion={TLSTester.supportedProtos()} and cryptoAlg={supportedCryptoAlgForIkeAuth}")
        taskList = []
        for tlsProto in TLSTester.supportedProtos():
            if restrictTls and tlsProto not in restrictTls:
                continue
            taskList.append(asyncio.create_task(testProto(host = host, port = port, dhAlg = [ selectedDhAlg ], cryptoAlg = supportedCryptoAlgForIkeAuth, prfAlg = supportedPrfAlg, authAlg = supportedAuthAlg, identity = identity, servername = sni, tlsVersion = tlsProto, logger = lambda msg, tlsProto=tlsProto: logger(f"TLS({tlsProto}): {msg}"), loadDebug = f"{tlsProto}.json")))
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


async def testProto(host, port, dhAlg, cryptoAlg, prfAlg, authAlg, identity = None, servername = None, tlsVersion = None, logger = lambda msg: print(msg), loadDebug = None, writeDebug = None):
    logger(f"testProto({host}:{port}, dh={dhAlg}, crypto={cryptoAlg}, prf={prfAlg}, auth={authAlg}, identity={identity}, servername={servername}, tlsVersion={tlsVersion}, loadDebug = {loadDebug})")

    debug = Debug(logger)
    if loadDebug and os.path.isfile(loadDebug):
        logger("successfully loaded from debug file")
        async with aiofiles.open(loadDebug, mode='r') as f:
            content = await f.read()
        debug.fromJson(content)

    if identity is not None:
        tlsHandler = TLSTester(proto=tlsVersion,servername=servername,debug=debug)
        eapHandler = EapWithTls(tlsHandler, identity)
    else:
        eapHandler = None

    ikeHandler = IKEv2WithEap(eapHandler, host, port, cryptoAlg, prfAlg, authAlg, dhAlg, identity, debug, logger = logger)

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
        if writeDebug:
            async with aiofiles.open(writeDebug, mode='w') as f:
                f.write(debug.toJson())
        else:
            logger(f"testProto debug output: {debug.toJson()}")
        del(ikeHandler)

    return result

if __name__ == '__main__':
    main()
