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
print('Generating a new 2048-bit RSA key pair for client...')
keypair = RSA.generate(2048)
save_publickey(keypair.publickey(), my_pubenckeyfile)
save_keypair(keypair, my_privenckeyfile)
print('Done')

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
	cmd_line = input('Type a command: ')
	cmd, add_info, filename = parse_cmd_line(cmd_line)
	if is_valid_cmd(cmd):
		payload = ''
		if filename != '':
			payload = encrypt_file(filename)
		msg = construct_msg(version, local_seq_num, cmd, load_publickey(server_pubenckeyfile), add_info, filename)
		send_message(msg)
	status, rcv = netif.receive_msg(blocking=False)
