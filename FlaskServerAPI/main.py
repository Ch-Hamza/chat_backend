from flask import Flask, request
from flask_restful import reqparse, abort, Api, Resource
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import json
import flask


from CAFunctions import CAFunctions
from LdapFunctions import LdapFunctions
from AuthenticationFunctions import AuthenticationFunctions
#from CryptoFunctions import CryptoFunctions


app = Flask(__name__)
api = Api(app)

socketio = SocketIO(app, cors_allowed_origins='*')

ldapFunctions = LdapFunctions()

path = os.path.dirname(__file__)
ca_cert = os.path.join(path, '../certificates/ca_cert.pem')
ca_key = os.path.join(path, '../certificates/ca_key.pem')

if not os.path.isfile(ca_cert) or not os.path.isfile(ca_key):
    caFunctions = CAFunctions(ca_cert, ca_key)
    caFunctions.generate_key(ca_key)
    caFunctions.generate_self_signed_certif('CA', 'CA', ca_cert)
else:
    caFunctions = CAFunctions(ca_cert, ca_key)

authentication = AuthenticationFunctions()

#crypto = CryptoFunctions()

CORS(app)

# shows a single user item and lets you delete a user item
class User(Resource):
    ######### LDAP
    def get(self, username):
        return ldapFunctions.get_user(username)

    def put(self, username):
        return ldapFunctions.modify_user(username)

    def delete(self, username):
        return ldapFunctions.delete_user(username)
    ######### LDAP

# shows a list of all users, and lets you POST to add new users
class UserList(Resource):
    ######### LDAP
    def get(self):
        return ldapFunctions.get_users()
        
    def post(self):
        return ldapFunctions.add_user()
    ######### LDAP

class Login(Resource):
    def post(self):
        return authentication.login()

class LoginDart(Resource):
    def post(self):
        return authentication.login_dart()

class Register(Resource):
    def post(self):
        return authentication.register()

class VerifyCert(Resource):
    def post(self, username):
        return authentication.verify_certif(username)
        
class Sign(Resource):
    def post(self):
        response = flask.make_response(caFunctions.sign_dart())
        response.headers['content-type'] = 'application/octet-stream'
        return response

class SignCSR(Resource):
    def post(self):
        response = flask.make_response(caFunctions.sign())
        response.headers['content-type'] = 'application/octet-stream'
        return response

api.add_resource(UserList, '/user')
api.add_resource(User, '/user/<username>')
api.add_resource(Login, '/login')
api.add_resource(LoginDart, '/loginDart')
api.add_resource(Register, '/register')
api.add_resource(VerifyCert, '/verify/<username>')
api.add_resource(Sign, '/sign')
api.add_resource(SignCSR, '/sign-csr')

@socketio.on('custom_send')
def send_message(msg):
    message = json.loads(msg)
    print(message)
    #cipher = crypto.encrypt(message['message'], message['receiver'], message['source'])
    #print(cipher)
    emit('custom_receive', {'data': message['data'], 'receiver': message['receiver'], 'source': message['source'], 'time': message['time']}, broadcast=True)

connected_users = {"connected_users": []}

@socketio.on('custom_connect')
def broadcast_connect(msg):
    message = json.loads(msg)
    print(message['sn'] + " connected")
    connected_users["connected_users"].append({'sn': message['sn']})
    print(connected_users)
    emit('broadcast_connect', connected_users, broadcast=True)

@socketio.on('custom_disconnect')
def broadcast_disconnect(msg):
    message = json.loads(msg)
    print(message['sn'] + " disconnected")
    #connected_users["connected_users"].pop(connected_users["connected_users"].index(message))
    emit('broadcast_disconnect', connected_users, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, host='192.168.1.113', debug=True)
    #app.run(debug=True)