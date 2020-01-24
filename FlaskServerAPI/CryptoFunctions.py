import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
from flask import request
import hashlib
import base64

class CryptoFunctions:

    def encrypt(self, msg, receiver, source):

        path = os.path.dirname(__file__)
        keyfile = os.path.join(path, '../certificates/' + receiver + '_key.pem')
        with open(keyfile, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        source_keyfile = os.path.join(path, '../certificates/' + source + '_key.pem')
        with open(source_keyfile, "rb") as f:
            source_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        public_key = private_key.public_key()

        #msg = bytes(msg) if not isinstance(msg, bytes) else msg
        ciphertext = public_key.encrypt(
            str.encode(msg)
        )

        signature = source_private_key.sign(
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        m = hashlib.sha256(str(msg).encode('utf-8'))
        hashed_msg = m.hexdigest()

        res = {'cipher': str(base64.b64encode(ciphertext)), 'signature': str(base64.b64encode(signature)), 'hashed_msg': hashed_msg}
        print(res)
        return res

    def decrypt(self, ciphertext, signature, hashed_msg, source, receiver):

        print("hh")
        print(ciphertext)
        print(signature)
        print(hashed_msg)
        path = os.path.dirname(__file__)
        source_keyfile = os.path.join(path, '../certificates/' + source + '_key.pem')
        with open(source_keyfile, "rb") as f:
            source_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        receiver_keyfile = os.path.join(path, '../certificates/' + receiver + '_key.pem')
        with open(receiver_keyfile, "rb") as f:
            receiver_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        public_key = source_private_key.public_key()
        try:
            verif = public_key.verify(
                signature,
                ciphertext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            verif = True


        print(len(ciphertext))
        plaintext = receiver_private_key.decrypt(
            str.encode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        integrity = False

        res = {'message': str(plaintext), 'signature': verif, 'integrity': integrity}
        print(res)
        return res

    def decrypt_message(self):
        msg_data = json.loads(request.data)
        return self.decrypt(msg_data['data']['cipher'], msg_data['data']['signature'], msg_data['data']['hashed_msg'], msg_data['source'], msg_data['receiver'])