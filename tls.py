from scapy.layers.tls.basefields import _tls_version_options, _tls_version
from scapy.layers.tls.handshake import TLSClientHello, TLS13ClientHello, TLSServerHello, TLS13ServerHello, TLSCertificate
from scapy.layers.tls.handshake_sslv2 import SSLv2ClientHello, SSLv2ServerHello
from scapy.layers.tls.extensions import TLS_Ext_SignatureAlgorithms,TLS_Ext_SupportedVersion_CH, TLS_Ext_ServerName, ServerName, TLS_Ext_SupportedGroups, TLS_Ext_PostHandshakeAuth, TLS_Ext_SupportedVersion_SH
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_CH, KeyShareEntry
from scapy.layers.tls.record import TLS, TLSAlert
from scapy.layers.tls.record_sslv2 import SSLv2
from scapy.layers.tls.record_tls13 import TLS13
from scapy.utils import randstring


from debug import Debug

class TLSTester:
    def __init__(self, proto="tls10", compression = False, ciphers = None, servername = None, debug = Debug()):
        self.proto = proto
        self.compression = compression
        self.ciphers = ciphers
        self.servername = servername
        self.reply = None
        self.selectedVersion = None
        self.selectedProto = None
        self.success = False
        self.servercerts = []
        self.debug = debug
        self.msgid = 0

    @classmethod
    def supportedProtos(cls):
        return _tls_version_options.keys()

    def handleFromRemote(self, data):
        self.debug.setOrCheck(f"tlsIn{self.msgid}", data)
        if data is None:
            ret = self.tlsInitialHandshake()
        else:
            ret = self.tlsReply(data)

        self.debug.setOrCheck(f"tlsOut{self.msgid}", ret)
        self.msgid = self.msgid + 1

        #if self.proto == "sslv2":
        #    tmp = SSLv2(ret)
        #elif self.proto < "tls13":
        #    tmp = TLS(ret)
        #else:
        #    tmp = TLS(ret)
        #tmp.show()

        return ret

    def tlsInitialHandshake(self):
        if self.proto not in _tls_version_options.keys():
            raise Exception(f"tls proto {self.proto} unsupported")
        iproto = _tls_version_options[self.proto]
    
        if self.proto == "sslv2":
            ch = SSLv2ClientHello(challenge=randstring(16))
            p = SSLv2()
            p.msg.append(ch)
        else:
            if self.proto < "tls13":
                chcls = TLSClientHello
                iprotoch = iproto
            else:
                chcls = TLS13ClientHello
                if self.ciphers is None:
                    self.ciphers = 0x1301
                iprotoch = None #_tls_version_options["tls12"]

            if self.ciphers is not None:
                ch = chcls(ciphers = self.ciphers, version = _tls_version[iprotoch] if iprotoch is not None else None)
            else:
                ch = chcls(version = _tls_version[iprotoch] if iprotoch is not None else None)
            ch.ext = []
            if self.proto == "tls12":
                ch.ext += [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"])]
            elif self.proto >= "tls13":
                ch.ext += TLS_Ext_SupportedVersion_CH(versions=[iproto])
                ch.ext += TLS_Ext_PostHandshakeAuth()
                supported_groups = ["secp256r1", "secp384r1", "x448"]
                ch.ext += TLS_Ext_SupportedGroups(groups=supported_groups)
                # Or secp256r1 otherwise
                curve = 23
                ch.ext += TLS_Ext_KeyShare_CH(
                    client_shares=[KeyShareEntry(group=curve)]
                )
                ch.ext += TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss",
                                                             "sha256+rsa"])
                if self.servername is None:
                    raise Exception("TLS1.3 requires SNI")

            if self.servername is not None:
                ch.ext += TLS_Ext_ServerName(
                    servernames=[ServerName(servername=self.servername)]
                )
    
            p = TLS() #version=_tls_version[iproto])
            p.msg.append(ch)

        return p.raw_stateful()

    # TLS13Certificate is encrypted in TLS 1.3 - decryption not implemented here
    def tlsReply(self, data):
        pck = TLS(data)
        #pck.show()

        self.reply = pck

        serverhello = None
        for msg in pck.msg:
            if isinstance(msg, (SSLv2ServerHello, TLSServerHello, TLS13ServerHello)):
                serverhello = msg
            if isinstance(msg, TLSCertificate):
                self.servercerts = msg.certs

        if serverhello is not None:
            _tls_version_options_inv = { v: k for k,v in _tls_version_options.items() }
            self.selectedVersion = _tls_version[serverhello.version]
            self.selectedProto = _tls_version_options_inv[serverhello.version]
            if isinstance(serverhello, SSLv2ServerHello):
                self.servercerts = serverhello.cert
            else:
                for ext in serverhello.ext:
                    if isinstance(ext, TLS_Ext_SupportedVersion_SH):
                        self.selectedVersion = _tls_version[ext.version]
                        self.selectedProto = _tls_version_options_inv[ext.version]

            self.success = True
        else:
            self.success = False


        p = TLSAlert(level=1, descr=0)
        return p.raw_stateful()


