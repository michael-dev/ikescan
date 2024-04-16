
from scapy.layers.eap import EAP, EAP_TLS

class EapWithTls:
    def __init__(self, tlsHandler, identity):
        self.tlsHandler = tlsHandler
        self.remainToSent = b""
        self.remainIn = None
        self.maxFragmentSize = 2048
        self.tlsStarted = False
        self.identity = identity

    def handleFromRemote(self, data):
        eapMsg = EAP(data)
        #print(eapMsg)
        if eapMsg.code == EAP.REQUEST:
            return self.handleEapRequest(eapMsg)
        elif eapMsg.code == EAP.SUCCESS:
            return True
        elif eap_message.code == EAP.FAILURE:
            return False

    def handleEapRequest(self, eap_request):
        if eap_request.type == 1:
            # identity request
            #print("EAP: handle identity request")
            return EAP(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type) / self.identity
        elif eap_request.type == 13:
            return self.handleEapTlsRequest(eap_request)
        else:
            raise Exception("unsupported EAP TLS message")

    def handleEapTlsRequest(self, eap_request):
        if len(self.remainToSent) > 0:
            #print("TLS: Sending next fragment of data...")
            assert(len(eap_request.tls_data) == 0)
            assert(eap_request.L == 0)
            assert(eap_request.M == 0)
            assert(eap_request.S == 0)
            assert(self.tlsStarted == True)
            return self.eapTlsReply(eap_request, False)

        if eap_request.S == 1:
            #print("start tls")
            assert(self.tlsStarted == False)
            self.remainIn = None
            self.tlsStarted = True
        else:
            if eap_request.L == 1:
                assert(len(self.remainIn) == 0) # remainIn is not None after tlsStarted has been set to True
                self.expectedLen = eap_request.tls_message_len
                assert(self.expectedLen > 0)

            self.remainIn += eap_request.tls_data

            if eap_request.M == 1:
                # more data to follow, sent ACK
                return EAP_TLS(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type, L=0, M=0, S=0, tls_data=b"")

        self.remainToSent = self.tlsHandler.handleFromRemote(self.remainIn)
        self.remainIn = b""

        return self.eapTlsReply(eap_request, True)

    def eapTlsReply(self, eap_request, withLen):
        tlsLen = len(self.remainToSent)
        dataToSent = self.remainToSent[:self.maxFragmentSize]
        self.remainToSent = self.remainToSent[self.maxFragmentSize:]
        hasMore = 1 if len(self.remainToSent) > 0 else 0

        if withLen:
            return EAP_TLS(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type, L=1, M=hasMore, S=0, tls_message_len=tlsLen, tls_data=dataToSent)
        else:
            return EAP_TLS(code=EAP.RESPONSE, id=eap_request.id, type=eap_request.type, L=0, M=hasMore, S=0, tls_data=dataToSent)

