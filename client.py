import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

NET_PATH = './network/'
OWN_ADDR = 'B'
my_pubenckeyfile = './network/A/pubenc.pem'
my_pubsigkeyfile = './network/A/pubsig.pem'
my_privenckeyfile = 'client_priv.pem'
statefile  = 'statefile.txt'
with open(statefile, 'rt') as sf:
	my_aeskey = bytes.fromhex(sf.readline()[len("key: "):len("key: ")+32])
server_pubenckeyfile = './network/B/pubenc.pem'
server_pubsigkeyfile = './network/B/pubsig.pem'
from_server_seq_num = 0
local_seq_num = 0
version = 0

# ------------
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python client.py')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python client.py')
		sys.exit(0)

print('Generating a new 2048-bit RSA key pair for client...')
keypair = RSA.generate(2048)
save_publickey(keypair.publickey(), my_pubenckeyfile)
save_keypair(keypair, my_privenckeyfile)

def send_message(msg):
	netif.send_msg('A', msg)

def encrypt_file(filename):
	inf = open(filename, 'r')
	payload = inf.read()
	payload = payload.encode('ascii')
	cipher = AES.new(my_aeskey, AES.MODE_GCM)
	ciphertext, mac = cipher.encrypt_and_digest(payload)
	nonce = cipher.nonce
	return nonce + mac + ciphertext

def decrypt_file(filename, bytestring):
	received_nonce = bytestring[:16]
	received_mac = bytestring[16:32]
	ciphertext = bytestring[32:]
	cipher = AES.new(my_aeskey, AES.MODE_GCM, received_nonce)
	plaintext = cipher.decrypt_and_verify(ciphertext, received_mac)
	f = open(filename, 'w')
	f.write(plaintext)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
while True:
	msg = input('Type a command: ')
	if msg == 'login':
		msg = construct_msg(version, local_seq_num, 'LGN', load_publickey(server_pubenckeyfile))
		send_message(msg)
	if msg == 'mkdir':
		name = input('Type new directory name: ')
		msg = construct_msg(version, local_seq_num, 'MKD', load_publickey(server_pubenckeyfile), name)
		send_message(msg)
	if msg == 'rmdir':
		name = input('Type directory to remove: ')
		msg = construct_msg(version, local_seq_num, 'RMD', load_publickey(server_pubenckeyfile), name)
		send_message(msg)
	if msg == 'gwd':
		msg = construct_msg(version, local_seq_num, 'GWD', load_publickey(server_pubenckeyfile))
		send_message(msg)
	if msg == 'cwd':
		name = input('Type folder to move to: ')
		msg = construct_msg(version, local_seq_num, 'GWD', load_publickey(server_pubenckeyfile), name)
		send_message(msg)
	if msg == 'lst':
		msg = construct_msg(version, local_seq_num, 'LST', load_publickey(server_pubenckeyfile))
		send_message(msg)
	if msg == 'upl':
		name = input('Type filename to upload: ')
		msg = construct_msg(version, local_seq_num, 'UPL', load_publickey(server_pubenckeyfile), name, encrypt_file(name))
		send_message(msg)
	if msg == 'dnl':
		name = input('Type filename to download: ')
		msg = construct_msg(version, local_seq_num, 'DNL', load_publickey(server_pubenckeyfile), name)
		send_message(msg)
	if msg == 'rmf':
		name = input('Type filename to remove: ')
		msg = construct_msg(version, local_seq_num, 'RMF', load_publickey(server_pubenckeyfile), name)
		send_message(msg)
	if msg == 'logout':
		msg = construct_msg(version, local_seq_num, 'LGO', load_publickey(server_pubenckeyfile))
		send_message(msg)
	status, rcv = netif.receive_msg(blocking=False)
