from LdapFunctions import LdapFunctions
from CAFunctions import CAFunctions
import json
from flask import request
import os

ldapFunctions = LdapFunctions()

path = os.path.dirname(__file__)
server_cert = os.path.join(path,'../certificates/ca_cert.pem')
server_key = os.path.join(path,'../certificates/ca_key.pem')
caFunctions = CAFunctions(server_cert, server_key)

class AuthenticationFunctions:

    def login(self):
        user_data = json.loads(request.data)
        user = ldapFunctions.login(user_data['username'], user_data['password'])
        print(user)
        if user!=None:
            return user
        else:
            return "Username or password is not correct"

    def login_dart(self):
        user_data = json.loads(request.data)
        user = ldapFunctions.login(user_data['username'], user_data['password'])
        if user!=None:
            return ldapFunctions.get_users()
        else:
            return user_data

    def generate_key(self, username):
        keyfile = os.path.join(path,'../certificates/' + username + '_key.pem')
        certfile = os.path.join(path,'../certificates/' + username + '_cert.pem')
        csrfile = os.path.join(path,'../certificates/' + username + '_csr.pem')
        #gen key
        pubkey = caFunctions.generate_key(keyfile)
        #gen certif
        csr = caFunctions.generate_client_csr(keyfile, username, certfile, csrfile)
        #sign certif
        signed_certif = caFunctions.sign(keyfile, username, certfile, csrfile)
        return {'pubkey': pubkey, 'csr': csr, 'signed_certif': signed_certif}

    def verify_certif(self, username):
        cert_pem = json.loads(request.data)
        verif = caFunctions.verify_certif(cert_pem)
        return verif

    def register(self):
        user_data = json.loads(request.data)
        print(user_data)
        result = ldapFunctions.add_user()
        return result