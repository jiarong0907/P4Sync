from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512


def rsa_sign(plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
    signer = PKCS1_v1_5.new(RSA.importKey(key))

    hash_value = hash_algorithm.new(plaintext)
    return signer.sign(hash_value)


def rsa_verify(sign, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
    hash_value = hash_algorithm.new(plaintext)
    verifier = PKCS1_v1_5.new(RSA.importKey(key))
    return verifier.verify(hash_value, sign)


if __name__ == '__main__':
    private_key = '''-----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQD1t3KRf4oS3sH8PbABbXL1KBYCnGq4C/yinpfQ2j2eUmZarHuw
    IMT9y5ns1lpZZTktGnypvnQjF8c0Rr/cYU53DJjglAgVEb3el6iU+WZ7nwLub/BN
    YS83zpzrhDE3Qy6qTM3evsUsekBR8x6f6Usl7KpEI/0b+EfRSpXDdvU64wIDAQAB
    AoGBAJK0odHfPTgBCf8pcaGYkG9xLJsIeutCNOd/GxOWif2yIux2WS8SkasaWd+/
    J5iCSD32t4G9dafSNZyvtTPGYUqll4aGXlFqNW8pm16HPQXWrhv1D5LVEEu3zbj+
    iNG+gHwB4bISQAOJbnvB6GoFUbDf8VYwkGGlSLGw5D5tulhRAkEA/XBLTfj+5j40
    QPfuRIhcBsgxynKJDcmV0sLAIOTBIfSKs5nuYHEVEOcGaxS+nPY3w1ffSUPUdxm0
    7L2s+9c0SQJBAPgzLLFvUjM58J/AtklkGyJ3KK5W+jLi/N1PIw7CGYGM2yfFiQLR
    ibtJVjTFhLKqDz/BK4lZ9ffU/VNHSApOncsCQQCRBzSgnw9GtGv0jaxUnW+EFgWg
    IyDYufW5kOafLCh1BNpmYnztxWhXrsyWdF2Ltr48U8mbxGwN57EIFJar2v+5AkA7
    GkSMRAv48tUf1Y4Sz+m+PU3Mph2SPIcmVA/vFb1pIheV0u4bY7Y+iOokStychu52
    qhMp8+gkie2BBTpcafgdAkBw8bAzLgmCV8SZEN60x8c2M2Y95CoYOoMLjvQdEfen
    IeDmun3DtAPBuStwYNfeQnAHCwvcOJsgDiRLzhys3056
    -----END RSA PRIVATE KEY-----'''

    public_key = '''-----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1t3KRf4oS3sH8PbABbXL1KBYC
    nGq4C/yinpfQ2j2eUmZarHuwIMT9y5ns1lpZZTktGnypvnQjF8c0Rr/cYU53DJjg
    lAgVEb3el6iU+WZ7nwLub/BNYS83zpzrhDE3Qy6qTM3evsUsekBR8x6f6Usl7KpE
    I/0b+EfRSpXDdvU64wIDAQAB
    -----END PUBLIC KEY-----'''

    message = '1111'
    signature = rsa_sign(message.encode(encoding='utf-8'), private_key)
    result = rsa_verify(signature, message.encode('utf-8'), public_key)
    print(result)