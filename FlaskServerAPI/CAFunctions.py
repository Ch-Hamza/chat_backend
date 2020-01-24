from cryptography import x509 
from argparse import ArgumentParser
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hashlib import sha3_512
from datetime import datetime, timedelta
import ipaddress
from uuid import uuid4
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric import padding
import os
import functools
import json
from flask import request
from OpenSSL import crypto
import base64
from ldap3 import MODIFY_REPLACE
import numpy as np

from LdapFunctions import LdapFunctions
ldapFunctions = LdapFunctions()

class CAFunctions:
    def __init__(self, ca_cert_path, ca_key_path):
        self.private_key = None
        self.ca_cert = None
        self.private_key_path = ca_key_path
        self.ca_cert_path = ca_cert_path
               
    def load_certif(self):
        with open(self.ca_cert_path,"rb") as f:
            self.ca_cert= x509.load_pem_x509_certificate(f.read(),default_backend())

    def load_private_key(self):
        if os.path.isfile(self.private_key_path):
            with open(self.private_key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            print("Wrong Path")

    def generate_key(self, keyfile):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(keyfile, "wb+") as f:
            f.write(key_pem)

        public_key = key.public_key()
        
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        print(pem)

        return pem

    def generate_client_csr(self, keyfile, username, certfile, csrfile):
        
        if os.path.isfile(keyfile):
            with open(keyfile, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            #set organisation name to issuer name
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, username),
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lafayette"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"INSAT"),
            ])

            #issuer = x509.Name([
            #    x509.NameAttribute(NameOID.COMMON_NAME, username)
            #])

            #build certif
            #basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
            #now = datetime.utcnow()

            csrbuilder = x509.CertificateSigningRequestBuilder()
            csrbuilder = csrbuilder.subject_name(subject)
            csrbuilder = csrbuilder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            csr = csrbuilder.sign(
                private_key, hashes.SHA256(), default_backend()
            )
            csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

            #certbuilder= certbuilder.subject_name(subject)
            #certbuilder = certbuilder.issuer_name(issuer)
            #certbuilder = certbuilder.public_key(private_key.public_key())
            #certbuilder = certbuilder.serial_number(int(uuid4()))
            #certbuilder = certbuilder.not_valid_before(now)
            #certbuilder = certbuilder.not_valid_after(now + timedelta(days=10*365))
            #certbuilder = certbuilder.add_extension(basic_contraints, False)
            
            #certificate = certbuilder.sign(private_key, hashes.SHA256(), default_backend())
            #cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

            with open(csrfile, "wb+") as f:
                f.write(csr_pem)

            print(csr_pem.decode("utf-8"))
            return csr_pem.decode("utf-8")

    #generate self signed certif
    def generate_self_signed_certif(self, subject_name, issuer, certfile):
        
        self.load_private_key()

        #set organisation name to issuer name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
        ])

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer)
        ])

        #build certif
        basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
        now = datetime.utcnow()
        certbuilder= x509.CertificateBuilder()
        certbuilder= certbuilder.subject_name(subject)
        certbuilder = certbuilder.issuer_name(issuer)
        certbuilder = certbuilder.public_key(self.private_key.public_key())
        certbuilder = certbuilder.serial_number(1)
        certbuilder = certbuilder.not_valid_before(now)
        certbuilder = certbuilder.not_valid_after(now + timedelta(days=10*365))
        certbuilder = certbuilder.add_extension(basic_contraints, False)
        
        certificate = certbuilder.sign(self.private_key, hashes.SHA256(), default_backend())
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

        with open(certfile, "wb+") as f:
            f.write(cert_pem)

        path = os.path.dirname(__file__)
        self.ca_cert_path = os.path.join(path,'../certificates/ca_cert.pem')
        self.load_certif()

    def get_public_key(self):
        return self.ca_cert.public_key()
    
    def get_CA_cert(self):
        return self.ca_cert

    def sign_dart(self):
        
        csr_data = request.data
        print(csr_data)

        csr = x509.load_pem_x509_csr(csr_data,default_backend())

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'CA')
        ])

         #build certif
        basic_contraints = x509.BasicConstraints(ca=False, path_length=None)
        now = datetime.utcnow()
        certbuilder= x509.CertificateBuilder()
        certbuilder= certbuilder.subject_name(csr.subject)
        certbuilder = certbuilder.issuer_name(issuer)
        certbuilder = certbuilder.public_key(csr.public_key())
        certbuilder = certbuilder.serial_number(int(uuid4()))
        certbuilder = certbuilder.not_valid_before(now - timedelta(days=1))
        certbuilder = certbuilder.not_valid_after(now + timedelta(days=10*365))
        certbuilder = certbuilder.add_extension(basic_contraints, False)
        
        self.load_private_key()
        certificate = certbuilder.sign(self.private_key, hashes.SHA256(), default_backend())
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

        numberlist = np.frombuffer(cert_pem, dtype='int8').tolist()
        print(cert_pem.decode("utf-8"))
        #print(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)

        try:
            ldapFunctions.connect()
            edits = {'userSMIMECertificate': [(MODIFY_REPLACE, str(numberlist))]}
            print(edits)

            res = ldapFunctions.conn.modify(
                dn='cn=' + csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value + ',ou=People,dc=insat,dc=chat,dc=com',
                changes=edits,
            )
            #print(res)
            print(ldapFunctions.conn.result)

            ldapFunctions.conn.unbind()
        except ldap3.LDAPError:
            ldapFunctions.conn.unbind()
        
        #with open(certfile, "wb+") as f:
            #f.write(cert_pem)

        print(len(cert_pem.decode("utf-8")))
        return cert_pem

    def sign(self):
        
        csr_data = request.data
        print(csr_data)

        csr = x509.load_pem_x509_csr(csr_data,default_backend())

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'CA')
        ])

        #build certif
        basic_contraints = x509.BasicConstraints(ca=False, path_length=None)
        now = datetime.utcnow()
        certbuilder = x509.CertificateBuilder()
        certbuilder = certbuilder.subject_name(csr.subject)
        certbuilder = certbuilder.issuer_name(issuer)
        certbuilder = certbuilder.public_key(csr.public_key())
        certbuilder = certbuilder.serial_number(int(uuid4()))
        certbuilder = certbuilder.not_valid_before(now - timedelta(days=1))
        certbuilder = certbuilder.not_valid_after(now + timedelta(days=10*365))
        certbuilder = certbuilder.add_extension(basic_contraints, False)
        
        self.load_private_key()
        certificate = certbuilder.sign(self.private_key, hashes.SHA256(), default_backend())
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        
        #cert_der = certificate.public_bytes(encoding=serialization.Encoding.DER)
        
        numberlist = np.frombuffer(cert_pem, dtype='int8').tolist()
        #print(cert_pem.decode("utf-8"))
        #print(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)

        try:
            ldapFunctions.connect()
            edits = {'userSMIMECertificate': [(MODIFY_REPLACE, str(numberlist))]}

            res = ldapFunctions.conn.modify(
                dn='cn=' + csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value + ',ou=People,dc=insat,dc=chat,dc=com',
                changes=edits,
            )
            #print(res)
            print(ldapFunctions.conn.result)

            ldapFunctions.conn.unbind()
        except ldap3.LDAPError:
            ldapFunctions.conn.unbind()

        return cert_pem

    def verify_certif(self, cert_pem):
        
        with open('../certificates/ca_cert.pem', 'rb') as root_cert_file:
            root_cert = root_cert_file.read()

        trusted_certs = [root_cert]
        verified = self.verify_chain_of_trust(cert_pem['cert_pem'], trusted_certs)

        if verified:
            print('Certificate verified')
            return True
        return False

    def verify_chain_of_trust(self, cert_pem, trusted_cert_pems):
        try:
            print(cert_pem)
            #cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            #print(cert)
            #base64.b64decode(cert_pem)
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

            # Create and fill a X509Sore with trusted certs
            store = crypto.X509Store()
            for trusted_cert_pem in trusted_cert_pems:
                trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
                store.add_cert(trusted_cert)

            # Create a X590StoreContext with the cert and trusted certs
            # and verify the the chain of trust
            store_ctx = crypto.X509StoreContext(store, certificate)
            # Returns None if certificate can be validated
            
            result = store_ctx.verify_certificate()

            if result is None:
                return True
            else:
                return False
        except:
            return False