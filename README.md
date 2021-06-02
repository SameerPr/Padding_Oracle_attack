# Padding_Oracle_attack
This is a python3 version of existing paddingoracle api from `Padding-oracle`. 

python-paddingoracle is an API that provides pentesters a customizable
alternative to `PadBuster`_ and other padding oracle exploit tools that can't
easily (without a heavy rewrite) be used in unique, per-app scenarios.

I have modified the file so that it can work with python3 version now.

#About Padding Oracle Attack
Padding oracle attack on CBC encryption
The standard implementation of CBC decryption in block ciphers is to decrypt all ciphertext blocks, validate the padding, remove the PKCS7 padding, and return the message's plaintext. If the server returns an "invalid padding" error instead of a generic "decryption failed" error, the attacker can use the server as a padding oracle to decrypt (and sometimes encrypt) messages.
more info `here`

Usage: 
------

See below for an example: ::

    from paddingoracle import BadPaddingException, PaddingOracle
    
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
            
    #encypt mode        
    teststring = b'givemetheflag'
    encrypted = padbuster.encrypt(teststring, block_size=AES.block_size)
    #return encypted teststring with help of oracle.
    
    #decrypt mode
    msg = text.split('\n')[5].encode()
    ctext = unhexlify(msg)  #cipher text received from server itself

    decrypted = padbuster.decrypt(ctext,block_size=AES.block_size)
    print("Plaintext after decryption:  %r" % (bytes(decrypted, )))
    
See file for an example.    

.. _`Padding-oracle`: https://github.com/truongkma/ctf-tools/tree/master/Padding-oracle
.. _`PadBuster`: https://github.com/GDSSecurity/PadBuster
.. _`here`: https://en.wikipedia.org/wiki/Padding_oracle_attack
