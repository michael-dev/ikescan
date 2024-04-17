from collections import namedtuple
from random import SystemRandom
from struct import pack, unpack, pack_into

import asyncio
import functools
import os
import socket

from scapy.contrib.ikev2 import *
from scapy.packet import NoPayload 
from scapy.supersocket import SimpleSocket

import scapy

from crypto import MODPDH, Crypto, Prf, Integrity, Cipher

Keyring = namedtuple('Keyring', ['sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr'])

class IKEv2Exception(Exception):
    pass

class IKEv2UnsupportedByServer(IKEv2Exception):
    pass

class IKEv2NoEapPayloadException(IKEv2Exception):
    pass

class IKEv2WithEap:
    EXCH_SA_INIT = 34
    EXCH_AUTH = 35
    
    cryptoAlgRange = range(36)
    prfAlgRange = range(10)
    authAlgRange = range(15)

    @classmethod
    def supportedDhAlg(cls):
        return MODPDH.supportedGroups()

    @classmethod
    def supportedCryptoAlg(cls):
        return Cipher.supportedAlg()

    @classmethod
    def algToText(cls, typeId, value):
        return IKEv2AttributeTypes[typeId][1][value]

    def __init__(self, eapHandler, server = "vpn.example.org", port = 500, cryptoAlg = [ 12 ], prfAlg = [2], authAlg =[2], dhAlg =[2], identity = "example@example.org", debugRandom = None):
        self.debugRandom = debugRandom
        self.eapHandler = eapHandler

        self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpsock.connect((server, port))
        self.udpsock.setblocking(False)

        self.myspi = bytes(RandString(8))
        if self.debugRandom is not None:
            self.myspi=bytes.fromhex(self.debugRandom["myspi"])

        self.cryptoAlg = cryptoAlg
        self.prfAlg = prfAlg
        self.authAlg = authAlg
        self.dhAlg = dhAlg
        self.identity = identity

        self.dh = { id : MODPDH(id, usePrecomputed=True) for id in self.dhAlg }
        if self.debugRandom is not None:
            self.dh[2].loadGroup(bytes(self.debugRandom["dh"], encoding='utf-8'))
            self.dh[2].loadKey(bytes(self.debugRandom["dhkey"], encoding='utf-8'))
        random = SystemRandom()
        noncelength = random.randrange(16, 256)
        self.nonce = os.urandom(noncelength)
        if self.debugRandom is not None:
            self.nonce=bytes.fromhex(self.debugRandom["nonce"])

        self.cookie = None

    def __del__(self):
        self.udpsock.close()

    async def doSaInit(self):
        self.msgid = 0

        proposals = [ 
            IKEv2_Transform( transform_type = 1, transform_id = id) for id in self.cryptoAlg #3=3DES, 12=AES_CBC
        ] + [
            IKEv2_Transform( transform_type = 3, transform_id = id) for id in self.authAlg  #HMAC_SHA1_96
        ] + [
            IKEv2_Transform( transform_type = 2, transform_id = id) for id in self.prfAlg  #PRF_HMAC_SHA1
        ] + [
            IKEv2_Transform( transform_type = 4, transform_id = id) for id in self.dhAlg  # DH Group
        ]
        proposals_layer = functools.reduce(lambda x, y: x / y, proposals)
    
        pck = IKEv2(init_SPI=self.myspi, exch_type=self.EXCH_SA_INIT, flags = ["Initiator"], id = self.msgid )
        if self.cookie is not None:
            #print('Adding cookie')
            pck = pck / self.cookie
        else:
            #print('Without cookie')
            pass
        pck = pck / IKEv2_SA(prop= IKEv2_Proposal(trans_nb = len(proposals), trans = proposals_layer ))
        #print(self.dh)
        for id, dhv in self.dh.items():
            #print(f"group = {dhv.group}, ke = {dhv.public_key.hex()}")
            if self.debugRandom is not None:
                assert(dhv.group == self.debugRandom["dhGroup"])
                assert(dhv.public_key.hex() == self.debugRandom["dhKe"])
            pck = pck / IKEv2_KE(group=dhv.group, ke = dhv.public_key)
        pck = pck / IKEv2_Nonce(nonce=self.nonce)
        
        #print(f"sending: {bytes(pck).hex()}")
        if self.debugRandom is not None:
            assert(bytes(pck).hex() == self.debugRandom["sending1"])

        if self.debugRandom is not None:
            print("fake result from peer")
            r = bytes.fromhex(self.debugRandom["received1"])
            r = IKEv2(r)
            self.msgid = self.msgid + 1
        else:
            r = await self.sendAndRecv(pck)
    
        rxMsg = r
        
        rxNotify = self.getPayloadByType(rxMsg, lambda x: type(x) == IKEv2_Notify, False)
        errors = [ x for x in rxNotify if x.type < 1024 ]
        if [ x for x in rxNotify if x.type == 14 ]:
            raise IKEv2UnsupportedByServer("no proposal choosen")
        if errors:
            raise IKEv2Exception("Errors: " + "\n".join( [ f"type={IKEv2NotifyMessageTypes[x.type] if x.type in IKEv2NotifyMessageTypes else str(x.type)} ({x.type}) msg={str(x)}" for x in errors ] ))

        rxCookie = [ x for x in rxNotify if x.type == 16390 ]
        if rxCookie:
            if self.cookie is not None:
                raise IKEv2Exception("SA INIT cookie changed")
            self.cookie, = rxCookie
            self.cookie = IKEv2_Notify(type = self.cookie.type, proto = self.cookie.proto, notify = self.cookie.notify)
            return self.doSaInit()

        rxSA = self.getPayloadByType(rxMsg, lambda x: type(x) == IKEv2_SA)
        rxNonce = self.getPayloadByType(rxMsg, lambda x: type(x) == IKEv2_Nonce)
        rxKE = { x.group : x for x in self.getPayloadByType(rxMsg, lambda x: type(x) == IKEv2_KE, False) }
        rxCertReq = self.getPayloadByType(rxMsg, lambda x: type(x) == IKEv2_CERTREQ, False)

        if len(rxKE) == 0:
            raise IKEv2Exception("Missing kE")

        if len(rxCertReq) > 0:
            raise IKEv2Exception("Certificate auth not implemented")

        # handle choosen proposal
        chosen_proposal = rxSA.prop
        if (type(chosen_proposal.payload) != NoPayload):
            raise IKEv2Exception("More than one proposal")
    
        t = chosen_proposal.trans

        try:
            self.chosenCryptoAlg = self.getPayloadByType(t, lambda x: x.transform_type == 1).transform_id
            self.chosenCryptoKeyLength = self.getPayloadByType(t, lambda x: x.transform_type == 1).key_length
            self.chosenPrfAlg = self.getPayloadByType(t, lambda x: x.transform_type == 2).transform_id
            self.chosenDhAlg = self.getPayloadByType(t, lambda x: x.transform_type == 4).transform_id
        except IKEv2Exception as ex:
            t.show()
            raise ex

        try:
            self.chosenAuthAlg = self.getPayloadByType(t, lambda x: x.transform_type == 3).transform_id
        except IKEv2Exception as ex:
            self.chosenAuthAlg = None
            # authenticated ciphers don't need this
            pass

        self.rxKEselected = rxKE[self.chosenDhAlg]
        self.dhSelected = self.dh[self.chosenDhAlg]
        if self.dhSelected is None or self.rxKEselected is None:
            raise IKEv2Exception("Diffie Hellmann mismatch")
    
        self.dhSelected.compute_secret(self.rxKEselected.ke)
        #print(f'Generated DH shared secret: {self.dhSelected.shared_secret.hex()}')
        if self.debugRandom is not None:
            assert(self.dhSelected.shared_secret.hex() == self.debugRandom["DH shared secret"])
    
        #print(f"got nonce {rxNonce.nonce.hex()}")
        if self.debugRandom:
            assert(rxNonce.nonce.hex() == self.debugRandom["rxNonce1"])
        self.rxNonce = rxNonce

        # update peer spi (take it from the payload SA if old_sa_d is not none ie. IKE_SA rekey)
        self.peer_spi = rxMsg.resp_SPI

    async def doSaAuth(self):
        # generate IKE SA key material
        self.generate_ike_sa_key_material()
   
        exit
        # send AUTH_REQUEST
        payload_idi = IKEv2_IDi(IDtype="Email_addr", ID=self.identity)
        payloads = payload_idi

        while payloads is not None:
            payloads = await self.doSaAuthWithPayload(payloads)

    async def doSaAuthWithPayload(self, payloads):
        #print(f"Sending {payloads} as id={self.msgid}")
        cleartext = bytes(payloads)
    
        # PayloadSK = just ciphertext
        iv = self.crypto_i.cipher.generate_iv()
        if self.debugRandom is not None:
            iv = bytes.fromhex(self.debugRandom[f"iv{self.msgid}"])
        #print(f"iv={iv.hex()}")
        padlen = (self.crypto_i.cipher.block_size - (len(cleartext) % self.crypto_i.cipher.block_size) - 1)
        cleartext += b'\x00' * padlen + pack('>B', padlen)
        encrypted = self.crypto_i.cipher.encrypt(self.crypto_i.sk_e, bytes(iv), bytes(cleartext))
        
        payload_type = None
        for pg in scapy.contrib.ikev2._IKEv2_Packet.payload_guess:
            if pg[1] == type(payloads):
                payload_type = pg[0]["next_payload"]
        if payload_type is None:
            #print(type(payloads))
            raise IKEv2Exception("not implemented payload to be sent")

        encrypted_payload = IKEv2_Encrypted(next_payload=payload_type, load=iv + encrypted + b'\x00' * self.crypto_i.integrity.hash_size)
        pck = IKEv2(init_SPI=self.myspi, resp_SPI=self.peer_spi, exch_type=self.EXCH_AUTH, flags = ["Initiator"], id = self.msgid ) / encrypted_payload
        data = bytearray(bytes(pck))
        checksum = self.crypto_i.integrity.compute(self.crypto_i.sk_a, data[:-self.crypto_i.integrity.hash_size])
        pack_into(f'>{len(checksum)}s', data, len(data) - len(checksum), checksum)
        pck = IKEv2(data)
        
        if self.debugRandom is not None:
            assert(bytes(pck).hex() == self.debugRandom["sending2"])
        r = await self.sendAndRecv(pck)
    
        #print(r)
        if(type(r.payload) != IKEv2_Encrypted):
            raise IKEv2Exception("answer to auth not encrypted")
 
        data = bytes(r)
        ciphertext = r.payload.load
 
        # check integrity
        checksum = self.crypto_r.integrity.compute(self.crypto_r.sk_a, data[:-self.crypto_r.integrity.hash_size])
        if checksum != data[-self.crypto_r.integrity.hash_size:]:
            raise IKEv2Exception("answer to auth has bad checksum")
 
        # parse decrypted payloads and remove Payload SK
        iv = ciphertext[:self.crypto_r.cipher.block_size]
        ciphertext = ciphertext[self.crypto_r.cipher.block_size:-self.crypto_r.integrity.hash_size]
        decrypted = self.crypto_r.cipher.decrypt(self.crypto_r.sk_e, bytes(iv), bytes(ciphertext))
        padlen = decrypted[-1]
        cleartext = decrypted[:-1 - padlen]
 
        decoded = (r.payload.guess_payload_class(None))(cleartext)
 
        #print(decoded)
        t = decoded
        rxNotify = self.getPayloadByType(t, lambda x: type(x) == IKEv2_Notify, False)
        errors = [ x for x in rxNotify if x.type < 1024]
        if errors:
            raise IKEv2Exception("Errors: " + "\n".join( [ f"type={IKEv2NotifyMessageTypes[x.type] if x.type in IKEv2NotifyMessageTypes else str(x.type)} ({x.type}) msg={str(x)}" for x in errors ] ))
   
        try:
            rxEAP = self.getPayloadByType(t, lambda x: type(x) == IKEv2_EAP)
        except IKEv2Exception as ex:
            raise IKEv2NoEapPayloadException(ex)
        reply = self.eapHandler.handleFromRemote(rxEAP.load)
        if reply == True:
            #print("EAP success")
            return None
        elif reply == False:
            #print("EAP failure")
            raise IKEv2Exception("EAP failed")
        
        eapReply = IKEv2_EAP(load = bytes(reply))
        
        return eapReply
    

    # taken from pyikev2 - GPLv3
    def generate_ike_sa_key_material(self):
        """ Generates IKE_SA key material based on the proposal and DH
        """
        nonce_i=self.nonce
        nonce_r=self.rxNonce.nonce
        spi_i=self.myspi
        spi_r=self.peer_spi
        shared_secret=self.dhSelected.shared_secret

        prf = Prf(self.chosenPrfAlg)
        integ = Integrity(self.chosenAuthAlg) if self.chosenAuthAlg else None
        cipher = Cipher(self.chosenCryptoAlg, self.chosenCryptoKeyLength)
    
        skeyseed = prf.prf(nonce_i + nonce_r, shared_secret)
    
        #print(f'Generated SKEYSEED: {skeyseed.hex()}')
        
        # will fail for authenticated encryption (GCM), as it has no extra integ algorithm
        # needs to be checked out

        keymat = prf.prfplus(skeyseed, nonce_i + nonce_r + spi_i + spi_r,
                             prf.key_size * 3 + integ.key_size * 2 + cipher.key_size * 2)
        sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = unpack(
            '>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(prf.key_size, integ.key_size, cipher.key_size), keymat)
        self.ike_sa_keyring = Keyring(sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr)
        self.crypto_i = Crypto(cipher, self.ike_sa_keyring.sk_ei, integ, self.ike_sa_keyring.sk_ai, prf, self.ike_sa_keyring.sk_pi)
        self.crypto_r = Crypto(cipher, self.ike_sa_keyring.sk_er, integ, self.ike_sa_keyring.sk_ar, prf, self.ike_sa_keyring.sk_pr)
    
        for keyname in ('sk_d', 'sk_ai', 'sk_ar', 'sk_ei', 'sk_er', 'sk_pi', 'sk_pr'):
            hexkey = getattr(self.ike_sa_keyring, keyname).hex()
            #print(f'Generated {keyname}: {hexkey}')

    def getPayloadByType(self, r, fnFilter, isUnique = True):
        ret = []
        while (not (type(r) == NoPayload)):
            if fnFilter(r):
                ret.append(r)
            r = r.payload

        if not isUnique:
            return ret

        if len(ret) != 1:
            raise IKEv2Exception(f"IKEv2 payoad type found {len(ret)} times != 1")
        return ret[0]

    async def sock_recvfrom(self, nonblocking_sock, *pos, **kw):
        loop = asyncio.get_event_loop()
        while True:
            try:
                return nonblocking_sock.recvfrom(*pos, **kw)
            except BlockingIOError:
                future = asyncio.Future(loop=loop)
                loop.add_reader(nonblocking_sock.fileno(), lambda : future.set_result(True) if not future.done() else None)
                try:
                    await asyncio.wait_for(future, timeout=1)
                finally:
                    loop.remove_reader(nonblocking_sock.fileno())

    async def sendAndRecv(self, pck):
        r = None
        for i in range(3):
            self.udpsock.send(bytes(pck))
            try:
                r, sender = await self.sock_recvfrom(self.udpsock, 65535)
                r = IKEv2(r)
                break
            except TimeoutError as ex:
                pass
        if r is None:
            raise IKEv2Exception("no answer")
        if r.answers(pck) == 0 or r.id != self.msgid: # requires init_SPI to be bytes
            #print(f"ids: {r.id} {self.msgid}")
            raise IKEv2Exception("answer does not match")
        self.msgid = self.msgid + 1
        return r

