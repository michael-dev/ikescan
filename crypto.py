#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Taken and stripped von pyikev2 - GPL v3

""" This module defines cryptographic classes
"""

import hashlib
import os
from hmac import HMAC

import cryptography.hazmat.backends.openssl.backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
from cryptography import x509

from cryptography.hazmat.primitives.serialization import load_pem_parameters, Encoding, ParameterFormat, NoEncryption, load_pem_private_key, PrivateFormat

class MODPDH:
    _group_dict = {
        1: # MODP768
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF',
        2: # MODP1024
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF',
        14: # MODP2048
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',

        15: # MODP3072
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CB'
            'A64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA'
            '06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108'
            'E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',

        16: # MODP4096
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CB'
            'A64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA'
            '06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108'
            'E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB'
            '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD'
            '0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF',

        17: # MODP6144
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3C'
            'D3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE'
            '9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208'
            '552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C5'
            '5DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CB'
            'A64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA'
            '06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108'
            'E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB'
            '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD'
            '0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763D'
            'BA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7'
            'F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F4698'
            '0C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5'
            'ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C04'
            '68043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF',

        18: # MODP8192
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
            '83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
            '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C'
            'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'
            '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6'
            '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'
            '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD'
            'F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B'
            'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6'
            'D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA'
            'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C'
            'DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4'
            '38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568'
            '3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B'
            '4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36'
            '4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92'
            '4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71'
            '60C980DD98EDD3DFFFFFFFFFFFFFFFFF',
    }
    # these are for testing / scanning purposes only! do not use to ensure confidentiality
    _precomputed_keys = {
1: """-----BEGIN PRIVATE KEY-----
MIHcAgEAMHMGCSqGSIb3DQEDATBmAmEA///////////JD9qiIWjCNMTGYouA3BzR
KQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF
5IW1dmJefsb0TELppjo2IP//////////AgECBGICYFHunnmho83MP0UyGyHzitC8
9kQNLER8NmeZ9elQZyqywL+LBeE415cfl7y9c3an6367YGDmWf6CptsuJBXQlpSJ
AXYi2scjffznQYxIAl0L/MMsA2C6fMvQkvVJ1qrnKQ==
-----END PRIVATE KEY-----
""",
2: """-----BEGIN PRIVATE KEY-----
MIIBIQIBADCBlQYJKoZIhvcNAQMBMIGHAoGBAP//////////yQ/aoiFowjTExmKL
gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt
bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR
7OZTgf//////////AgECBIGDAoGARGvMN1n8fWLNO/t4L0eE2FTySZlpGhGtLvRP
0EOJI54rJ++sx6eUVMbMR6yKfXwBt54Uh3bvc2jAcTvfqUu0A3a7oSRVAcfONv4b
/Hx1KCT3eF2EOAS/XGa/4A/EdoGh39xuA78ruzE6LQbbRsDTNaeTEsBQ1NOeWX9G
0ApFvbs=
-----END PRIVATE KEY-----
""",
14: """-----BEGIN PRIVATE KEY-----
MIICJgIBADCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////yQ/aoiFowjTE
xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP
4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ
KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue
1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1
xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKrKpo//////////8C
AQIEggEEAoIBAH+pQbdDstInkhXTJ63Z7r5P3jCCEAh7P7RPfA2vM1cbhXLgzk+m
WrrA6VB2XbX/CgStKoYX8MgYiP66NTdnUzKt08817dvHbM0af9gv1MXSxozUNDMP
O3U5WifVkwGqewUq9EomUjHjv1onVcYr+1PnoJxFLjbc3qEWsK80XB/fkqpBIUMk
JUQ/yJGPR3bwu+WuiKM8oUPESkYe8jebcisOOehjQrClsIstaQoVzw/cTpP1UR/f
Yy30RNaBAUIN6RzsRK4k+oDGILd6+nU9L5ko1ZvG6B1xZ6Tdk2CftMFzamPkPVdX
2aTq5KQSGSALYb125+vfhYvpUPIroZ8eesY=
-----END PRIVATE KEY-----
""",
15: """-----BEGIN PRIVATE KEY-----
MIIDJgIBADCCAZcGCSqGSIb3DQEDATCCAYgCggGBAP//////////yQ/aoiFowjTE
xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP
4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ
KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue
1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1
xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo
VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O
49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII
4k+gdOWrMUPbW/zg/RCOS4LRIKk60sr//////////wIBAgSCAYQCggGAdjFcDKhr
8xWlzpUlBWQTPCUQwkV1GLRp+1/LfyVvGWr3dk2ylHjn2XAmsC3py+2z9tsZowD3
9NnGpxjyP5/pFXeDPNd8QvtRGdgNIrZFiSEIaND+S7CgKgjMdyT7+E36r1ts24g2
l/6em9C80SBae/zt3dHbyySlFjxrg3SRXeJ6Vyja4Qv5vQrsqwz7064a2NcxAWdv
vxVOFYHID+nmwT4yY9eIkjgOsg4kUuSgDY9mM7OHXupkf1TSIGblog2IcvO3oNw4
ijbtXJ9ag7w6BklQtRFnbwMeAbAhd5y1TF7lDSN3PCo4HV6pMjMvvQL7fMt//fgf
VqMOYbrkhOe4mMzU82TBiNkbLBr93IjenTMGL8oxDU5Nh7SpMZ3Dvlf6TtPFYyGB
5RGEZZ2XuyUcPu5o4mL5uNG8Xyzt/e/PX8UPvIgkMXAl27/J5Q7jpqVd2qK3LMMW
EHgKwDWSI1NItHfuH2SHaDqmglSYVUkKhJy7pDviC4nwZflQpZ7/EMyT
-----END PRIVATE KEY-----
""",
16: """-----BEGIN PRIVATE KEY-----
MIIEJgIBADCCAhcGCSqGSIb3DQEDATCCAggCggIBAP//////////yQ/aoiFowjTE
xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP
4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ
KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue
1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1
xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo
VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O
49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII
4k+gdOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwa
lGg0thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6Ij
O6GGUVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N
9DXJNAYxmf//////////AgECBIICBAKCAgANilfojm3hZ48iZIL7EpPkJ623XCXc
FkkFc08gOqCnUC8MhJ/+poEra3+ioTuPmg4N0IGzB5r7J8gNxBakRqWHgYmbaQdO
MH24md/m0w1kz3q3seYS/+ZdlaX3OrNYEx4iGNf76aQz4t7cNaVfs9YUK2aBsHUn
jO/ZRSfEL0qJAeMJOPb8bW1CdrD3C46hDYi8bl+ARmDhDpzZRGWW0ba7ht8OvCUL
qeejUFMNesEpetNI0ihP0FvjXV9yy2FI1dlfb1HxICvSyYCg99Y6B1DJc6MkDq/v
QcCPRGJrpTKOYaHYKF1FsbVwABvnfeRfu5Z83r4E1YT8cCzZWNuCFYaLDD+nlf2T
i6JNxXRVoK0NRBG49gSv2s/nJaoTr9rsInes2SDGL3c0q1JDUfSkJlbP6ZjfsCMD
/T5TsL9KrC4yMW4JOJvAwR511B431hejmbn5GTjMxrXbQ00ggIsd2DhjhC/P6rCK
tcUMJcH0F/Mgjc51ye20WHU/kCraZwtectrgmKsxlYBA6TaJkp0j7xD2iXL7NuTg
3wYocRzNW4eUAB0bdrQ1QuOFqOqq0JH+wFQktWDa8A1QmNWuiU63/RFtjJU6/49W
gn5/kneZ33K1M3SzcX01SXT6j9kDMgHQSm1upZvNw/lUNz75J2UgCTnBB8jLzawv
9zy7cPQJOZFrgQ==
-----END PRIVATE KEY-----
""",
17: """-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
""",
18: """-----BEGIN PRIVATE KEY-----
MIIIJgIBADCCBBcGCSqGSIb3DQEDATCCBAgCggQBAP//////////yQ/aoiFowjTE
xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP
4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ
KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue
1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1
xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo
VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O
49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII
4k+gdOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwa
lGg0thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6Ij
O6GGUVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N
9DXJNAKEkjbD+rTSfHAmwdTcsmAmRt7JdR52Pbo3vfj/lAatnlMO5ds4L0EwAa6w
alPtkCfYMReXJ7CGWokY2j7b68+bFO1Ezmy6ztS7G9t/FEfmzCVLMyBRUSvXr0Jv
uPQBN4zSv1mDygHGS5Ls8DLqFdFyHQP0gtfObnT+9tVecC9GmAyCtahAMZALHJ5Z
58l/vsfo8yOpen42zIi+Dx1Ft/9YWsVL1AeyK0FUqsyPbX6/SOHYFMxe0g+AN+Cn
lxXu8pvjKAah1Yu3xdp29VCqPYofv/DrGcyxoxPVXNpWyewu8pYyOH/o1248BGgE
Po9mP0hg7hK/LVsLdHTW5pT5Hm2+EVl0o5JvEv7l5Dh3fLapMt+M2L7E0HO5Mbo7
yDK2jZ3TAHQfp7+K/EftJXb2k2ukJGY6q2OcWuT1aDQjtHQr8cl4I48Wy+OdZS3j
/bi+/ISK2SIiLgSkA3wHE+tXqBoj8Mc0c/xkbOowa0vLyIYvg4Xd+p1Lf6LAh+h5
aDMD7VvdOgYrPPWzonimbSoT+D9E+C3fMQ7gdKtqNkWX6JmgJV3BZPMcxQhGhR35
q0gZXe1+obHVEL1+501z+vNrwx7Pomg1kEb064efkkAJQ4tIHGzXiJoALtXuOCvJ
GQ2m/AJuR5VY5EdWd+mqnjBQ4nZWlN/IH1bogLlucWDJgN2Y7dPf//////////8C
AQIEggQEAoIEABj72UDPqB7MKnPkUf8dg9+Epd9XdmpBWz1wFRAvgLx1Il9nUt3/
XE+Cb2y2QMwM3U3IdXvXU+c4VVklsn6u29vOE8Ge7uulrkW2G+duDNhkVoUthsP6
C9GJHNQfI0q+VQWtd2+dJj/nKdQ9z29tbF5iBqk3zPoJvmPWtFlqASyaRIgqP5Ik
tUG34+VCOztl5bwm6akYSB+u5t372w7ISne196vHhbM1yjlhftueVn20iDqFP6YO
zrYguupA+DZoSwLgQ0wJ/Nkqjnb41SkERxn7muguWqQC19vMsXirBqukS7xRt/oX
PnoXez+coJHaCiQQ3C4myqG2tJZ2hlyf8zKJNCXMsqaq5JkgkVpiLZ/ykz3n0SHv
x4LMI2yWDz+1jrYMYeLHI91CxloWN8fRUC/D3nB1XtOD5jlOxFObC8wrdmJ0NPcs
3Aw4SXVQTMXRQ34juyUtywk2cT94ko56Wx7bpTmcpDZGj86jqzw8LAt1OIPp/SRn
+8JQ5uRnNXEz8grxASBGmicdmKQX6o020F3WHPnxJGmgojvrrSvQ0NGIQ7oFcB+Q
ctL5Dc/MrQ1B4XvdY+1zgM+qFgGBjW4I6daSghqY079xxrwovg2ORp+nB+CF5EdV
Y1VoGs1sOX1xEY+2WT84/A6FCKD2Q85RNYNpLYRV4htSifojzXMBDIKPIdLEOC3w
PhiTMn2oK+/MB/67T0kQxrBDSS3lUyx4L2LODJ/kC0hVku5Hz2MZxPs+OcQi/fAk
0SdEc8RK762y8+2PZAhegvyXKWw35mn2h4cjCbth+cLLjr7+TodLB2SumuyS940i
BI0Zvofx0ZSHWg1MXmd28kao40NwJg2ls4b4DFdFRjcO95/Y23b4FPUan9U+wdT7
79yc9Auv55hic9Lj0CLa9GTjWaXepwlW8sXi6rjv1twYF+pb3Cuv0U1CY4hkpB2c
hjUdCBLsgPjiFnBPoVKz8u2Wm2DGEpeuCYFqaG9simpIzAqxb/fuPF9f916ADtuP
56Zg4cSERPDoCjOSI3rfuudKRFYVHgY045OULDP2JQKr9OZhYzio+4EqMCzwmGSD
hBHrwM/YzVy7/SzKDAUZ4cHQcoprEKPpn64K3ABqQ3CLeVgAHBamyUdVEXEB1Rdf
jhn8GE3MJqw+cYE0r5tmqjfOBmpVknAGG9KJtZOJ9/B7wZuJqzEDKZFUG+GrnCjK
6/4MMcMqJ9Cb+b7rlIKKScoA/Os5oXWZNtkUohipI+9r7nbyYyXtVvtEsLwRI4eA
QFRzMM7IZwgIuQHUkkTMV5Wm4WcEfNGV0NZSUeZ0deg+MwlgXxzQYErFYZTqCzEP
rtgJLtLQMpAw9vAMjzS0RjoM4Ydnbj62upQ=
-----END PRIVATE KEY-----
""",
            }

    backend = cryptography.hazmat.backends.openssl.backend

    def __init__(self, group, usePrecomputed=False):
        self.group = group
        self.key_len = len(self._group_dict[group]) // 2
        module = int(self._group_dict[self.group], 16)
        self._pn = dh.DHParameterNumbers(module, 2)
        self._parameters = self._pn.parameters(self.backend)
        self.shared_secret = None
        if usePrecomputed and group in self._precomputed_keys:
            self._loadKey(self._precomputed_keys[group].encode('utf-8'))
        else:
            self._generatePrivateKey()
            if usePrecomputed:
                print(f'{group}: """{self.exportKey().decode("utf-8")}""",')

    def compute_secret(self, peer_public_key):
        peer_public_key_int = int.from_bytes(peer_public_key, 'big')
        peer_public_numbers = dh.DHPublicNumbers(peer_public_key_int, self._pn)
        peer_public_key = peer_public_numbers.public_key(self.backend)
        self.shared_secret = self._private_key.exchange(peer_public_key)

    def exportGroup(self):
        return self._parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

    def exportKey(self):
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def loadGroup(self, data):
        self._parameters = load_pem_parameters(data)
        self._generatePrivateKey()
        self._refreshPublicKey()

    def _loadKey(self, data):
        self._private_key = load_pem_private_key(data, None)
        self._refreshPublicKey()
    
    def _generatePrivateKey(self):
        self._private_key = self._parameters.generate_private_key()
        self._refreshPublicKey()

    def _refreshPublicKey(self):
        public_key_int = self._private_key.public_key().public_numbers().y
        self.public_key = public_key_int.to_bytes(self.key_len, 'big')

    def loadKey(self, data):
        self._loadKey(data)

    @classmethod
    def supportedGroups(cls):
        return cls._group_dict.keys()

class ECDH:
    _ec_groups = {
        19: ec.SECP256R1(),
        20: ec.SECP384R1(),
        21: ec.SECP521R1(),
    }

    backend = cryptography.hazmat.backends.openssl.backend

    def __init__(self, group):
        self.group = group
        self._private_key = ec.generate_private_key(self._ec_groups[group], backend=self.backend)
        # Trick to get the ceil of the division
        self.key_len = (self._private_key.key_size + 7) // 8
        self.shared_secret = None
        public_numbers = self._private_key.public_key().public_numbers()
        self.public_key = (public_numbers.x.to_bytes(self.key_len, 'big')
                           + public_numbers.y.to_bytes(self.key_len, 'big'))

    def compute_secret(self, peer_public_key):
        x = int.from_bytes(peer_public_key[:self.key_len], 'big')
        y = int.from_bytes(peer_public_key[self.key_len:], 'big')
        peer_public_numbers = ec.EllipticCurvePublicNumbers(x, y, self._ec_groups[self.group])
        peer_public_key = peer_public_numbers.public_key(self.backend)
        self.shared_secret = self._private_key.exchange(ec.ECDH(), peer_public_key)


class DiffieHellman:
    @classmethod
    def from_group(cls, group):
        try:
            return MODPDH(group)
        except KeyError:
            return ECDH(group)

PRF_HMAC_MD5 = 1
PRF_HMAC_SHA1 = 2
PRF_HMAC_TIGER = 3
PRF_AES128_XCBC = 4
PRF_HMAC_SHA2_256 = 5
PRF_HMAC_SHA2_384 = 6
PRF_HMAC_SHA2_512 = 7
PRF_AES128_CMAC = 8
PRF_HMAC_STREEBOG_512 = 9

class Prf(object):
    _digestmod_dict = {
        PRF_HMAC_SHA1: hashlib.sha1,
        PRF_HMAC_SHA2_256: hashlib.sha256,
        PRF_HMAC_SHA2_512: hashlib.sha512,
    }

    def __init__(self, transform):
        self.hasher = self._digestmod_dict[transform]

    @property
    def key_size(self):
        return self.hash_size

    @property
    def hash_size(self):
        return self.hasher().digest_size

    def prf(self, key, data):
        m = HMAC(key, data, digestmod=self.hasher)
        return m.digest()

    def prfplus(self, key, seed, size):
        result = bytes()
        temp = bytes()
        i = 1
        while len(result) < size:
            temp = self.prf(key, temp + seed + i.to_bytes(1, 'big'))
            result += temp
            i += 1
        return result[:size]

ENCR_AES_CBC = 12
class Cipher:
    _algorithm_dict = {
        ENCR_AES_CBC: algorithms.AES,
    }

    _backend = cryptography.hazmat.backends.openssl.backend

    @classmethod
    def supportedAlg(cls):
        return cls._algorithm_dict.keys()

    def __init__(self, transform, key_length = None):
        self._algorithm = self._algorithm_dict[transform]
        self._key_length = key_length
        # establish whether transform.keylen attribute is valid
        if key_length is not None:
            if len(self._algorithm.key_sizes) == 1:
                raise InvalidSyntax(
                    f'Algorithm {self._algorithm.name} only accepts one keylen but KEY_LEN attribute is provided.')
            if key_length not in self._algorithm.key_sizes:
                raise InvalidSyntax(f'Incorrect key length {transform.keylen} for algorithm {self._algorithm.name}. '
                                    f'Acceptable values are: {self._algorithm.key_sizes}')
        elif len(self._algorithm.key_sizes) > 1:
            raise('Algorithm {} requires a KEY_LEN attribute'.format(self._algorithm.name))

    @property
    def block_size(self):
        return self._algorithm.block_size // 8

    @property
    def key_size(self):
        # if no KEYLEN attribute is present, return the first possible one
        return (self._key_length or self._algorithm.key_sizes[0]) // 8

    def encrypt(self, key, iv, data):
        if len(key) != self.key_size:
            raise EncrError('Key must be of the indicated size {}'.format(self.key_size))
        _cipher = _Cipher(self._algorithm(key), modes.CBC(iv), backend=self._backend)
        encryptor = _cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, key, iv, data):
        if len(key) != self.key_size:
            raise EncrError('Key must be of the indicated size {}'.format(self.key_size))
        _cipher = _Cipher(self._algorithm(key), modes.CBC(iv), backend=self._backend)
        decryptor = _cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def generate_iv(self):
        return os.urandom(self.block_size)

AUTH_HMAC_SHA1_96 = 2
AUTH_HMAC_SHA2_256_128 = 12
AUTH_HMAC_SHA2_512_256 = 14
class Integrity:
    _digestmod_dict = {
        AUTH_HMAC_SHA1_96: (hashlib.sha1, 96),
        AUTH_HMAC_SHA2_256_128: (hashlib.sha256, 128),
        AUTH_HMAC_SHA2_512_256: (hashlib.sha512, 256),
    }

    def __init__(self, transform):
        self.hasher, self.keybits = self._digestmod_dict[transform]

    @property
    def key_size(self):
        return self.hasher().digest_size

    @property
    def hash_size(self):
        # Hardcoded as we only support _96 algorithms so far
        return self.keybits // 8

    def compute(self, key, data):
        m = HMAC(key, data, digestmod=self.hasher)
        return m.digest()[:self.hash_size]


class Crypto:
    def __init__(self, cipher, sk_e, integrity, sk_a, prf, sk_p):
        self.cipher = cipher
        self.sk_e = sk_e
        self.integrity = integrity
        self.sk_a = sk_a
        self.prf = prf
        self.sk_p = sk_p

