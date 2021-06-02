from itertools import  cycle
import logging
from Crypto.Random import get_random_bytes
from pwn import *
from binascii import hexlify, unhexlify
import os
from Crypto.Cipher import AES


__all__ = [
    'BadPaddingException',
    'PaddingOracle',
    ]

class BadPaddingException(Exception):
    '''
    Raised when a blackbox decryptor reveals a padding oracle.

    This Exception type should be raised in :meth:`.PaddingOracle.oracle`.
    '''

class PaddingOracle(object):
    def __init__(self, **kwargs):
        self.log = logging.getLogger(self.__class__.__name__)
        self.max_retries = int(kwargs.get('max_retries', 3))
        self.attempts = 0
        self.history = []
        self._decrypted = None
        self._encrypted = None

    def oracle(self, data, **kwargs):
        raise NotImplementedError

    def analyze(self, **kwargs):
        raise NotImplementedError

    def encrypt(self, plaintext, block_size=16, iv=None, **kwargs):
        pad = block_size - (len(plaintext) % block_size)
        plaintext = bytearray(plaintext + (chr(pad) * pad).encode())

        self.log.debug('Attempting to encrypt %r bytes', str(plaintext))

        if iv is not None:
            iv = bytearray(iv)
        else:
            iv = bytearray(block_size)

        self._encrypted = encrypted = iv
        block = encrypted

        n = len(plaintext + iv)
        while n > 0:
            intermediate_bytes = self.bust(block, block_size=block_size,**kwargs)
            block = xor(intermediate_bytes,plaintext[n - block_size * 2:n + block_size])
            encrypted = block + encrypted
            n -= block_size 
        return encrypted

    def decrypt(self, ciphertext, block_size=8, iv=None, **kwargs):
        ciphertext = bytearray(ciphertext)
        self.log.debug('Attempting to decrypt %r bytes', str(ciphertext))
        assert len(ciphertext) % block_size == 0, \
            "Ciphertext not of block size %d" % (block_size, )

        if iv is not None:
            iv, ctext = bytearray(iv), ciphertext
        else:
            iv, ctext = ciphertext[:block_size], ciphertext[block_size:]

        self._decrypted = decrypted = bytearray(len(ctext))
        n = 0
        while ctext:
            block, ctext = ctext[:block_size], ctext[block_size:]
            intermediate_bytes = self.bust(block, block_size=block_size,**kwargs)
            decrypted[n:n + block_size] = xor(intermediate_bytes, iv)
            self.log.info('Decrypted block %d: %r',
                          n / block_size, str(decrypted[n:n + block_size]))
            iv = block
            n += block_size   

        return decrypted 
    
    def bust(self, block, block_size=16, **kwargs):
        intermediate_bytes = bytearray(block_size)
        test_bytes = bytearray(block_size)  
        test_bytes.extend(block)

        self.log.debug('Processing block %r', str(block))

        retries = 0
        last_ok = 0
        while retries < self.max_retries:
            for byte_num in reversed(range(block_size)):
                self.history = []
                r = 256
                if byte_num == block_size - 1 and last_ok > 0:
                    r = last_ok
                for i in reversed(range(r)):
                    test_bytes[byte_num] = i
                    try:
                        self.attempts += 1
                        self.oracle(test_bytes[:], **kwargs)
                        if byte_num == block_size - 1:
                            last_ok = i
                    except BadPaddingException:
                        if self.analyze is True:
                            raise
                        else:
                            continue
                    except Exception as e:
                        self.log.exception('Caught unhandled exception!\n'
                                           'Decrypted bytes so far: %r\n'
                                           'Current variables: %r\n'
                                           'error :%r\n',
                                           intermediate_bytes, self.__dict__,e)
                        raise
                    current_pad_byte = block_size - byte_num
                    next_pad_byte = block_size - byte_num + 1
                    decrypted_byte = test_bytes[byte_num] ^ current_pad_byte
                    intermediate_bytes[byte_num] = decrypted_byte
                    for k in range(byte_num, block_size):
                        test_bytes[k] ^= current_pad_byte
                        test_bytes[k] ^= next_pad_byte
                    break
                else:
                    self.log.debug("byte %d not found, restarting" % byte_num)
                    retries += 1
                    break
            else:
                break
        else:
            raise RuntimeError('Could not decrypt byte %d in %r within '
                               'maximum allotted retries (%d)' % (
                               byte_num, block, self.max_retries))
        return intermediate_bytes


def xor(data, key):
    return bytearray([x ^ y for x, y in zip(data, cycle(key))])


def test():
    class PadBuster(PaddingOracle):
        '''
        Implement Your Oracle here;
        conn is server which unhexlify received data first
        '''
        def oracle(self, data):
            s = bytes(data)
            s = hexlify(s) #since data get unhexlify before decrypt on server for me.
            conn.sendline(s)
            out = conn.recvuntil(">>").decode().split('\n')
            if "invalid padding" in out[0]:     #if oracle return invalid padding or message like this
                raise BadPaddingException
            return


    # conn = remote(host, port)
    # text = conn.recvuntil(">>").decode()
    
    print("\nTesting padding oracle exploit in DECRYPT mode")

    conn = process(['python3','poodle1.py'])
    text = conn.recvuntil(">>").decode()        
    padbuster = PadBuster()

    msg = text.split('\n')[5].encode()
    ctext = unhexlify(msg)  #cipher text received from server itself

    decrypted = padbuster.decrypt(ctext,block_size=AES.block_size)
    print("Plaintext after decryption:  %r" % (bytes(decrypted, )))

    
    print("\nTesting padding oracle exploit in ENCRYPT mode")

    ''' local server '''
    conn = process(['python3','poodle2.py'])
    text = conn.recvuntil(">>").decode()        
    
    padbuster = PadBuster()

    key = get_random_bytes(AES.block_size)
    iv = get_random_bytes(AES.block_size)

    teststring = b'givemetheflag' #need to encrypt it and send this to server

    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted = padbuster.encrypt(teststring, block_size=AES.block_size)

    print("Plaintext:  %r" % (teststring, ))
    print("Ciphertext: %r" % (bytes(encrypted), ))

    ''' Sending Ciphertext to get the flag '''
    s = bytes(encrypted)
    s = hexlify(s)
    conn.sendline(s)
    out = conn.recvuntil(">>").decode().split('\n')
    print("\n server sent:",out[0])

    print("\nRecovered in %d attempts" % (padbuster.attempts, ))

if __name__ == '__main__':
    test()
