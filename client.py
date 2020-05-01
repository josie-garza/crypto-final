import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

NET_PATH = './network/'
OWN_ADDR = 'B'
SERVER_ADDR='A'
my_pubenckeyfile = './server/keys/client/pubenc.pem'
my_pubsigkeyfile = './server/keys/client/pubsig.pem'
my_privenckeyfile = './client/keys/client/privenc.pem'
my_privsigkeyfile = './client/keys/client/privsig.pem'
my_privaeskeyfile  = './client/keys/client/privaes.txt'
server_pubenckeyfile = './server/keys/server/pubenc.pem'
server_pubsigkeyfile = './server/keys/server/pubsig.pem'
from_server_seq_num = 0
local_seq_num = 0

# ------------
# main program
# ------------
print('Generating a new 2048-bit RSA key pair for client...')
keypair = RSA.generate(2048)
save_publickey(keypair.publickey(), my_pubenckeyfile)
save_keypair(keypair, my_privenckeyfile)
print('Done')

def get_aes_key():
	with open(my_privaeskeyfile, 'rt') as sf:
		return bytes.fromhex(sf.readline()[len("key: "):len("key: ")+32])

def encrypt_file(filename):
	"""
	Encrypted the file under the given filename with GCM encryption.
	"""
	inf = open(filename, 'r')
	payload = inf.read()
	payload = payload.encode('ascii')
	cipher = AES.new(get_aes_key(), AES.MODE_GCM)
	ciphertext, mac = cipher.encrypt_and_digest(payload)
	nonce = cipher.nonce
	return nonce + mac + ciphertext

def decrypt_file(filename, bytestring):
	"""
	Decrypt the given bytes using GCM and save to the given filename.
	"""
	received_nonce = bytestring[:16]
	received_mac = bytestring[16:32]
	ciphertext = bytestring[32:]
	cipher = AES.new(get_aes_key(), AES.MODE_GCM, received_nonce)
	plaintext = cipher.decrypt_and_verify(ciphertext, received_mac)
	f = open(filename, 'w')
	f.write(plaintext)

def handle_seq_num(received_seq_num):
	if received_seq_num < local_seq_num:
		msg = construct_msg(get_ver_num(), local_seq_num, "OOS", load_RSA_key(server_pubenckeyfile))
		netif.send_msg(SERVER_ADDR, msg)
		return -1
	else:
		return 1

def process_command(cmd, add_info, file):
	if cmd == 'SCS': # on login success
		local_seq_num = 0								   ## IDK if this is right
	elif cmd == 'SUC':
		print("Success messaged received\n")
	elif cmd == 'REP':
		if file:										 ## IDK if this is right, how am i supposed to differentiate between
			decrypt_file(add_info, file)				## a rep with a file and one without a file?
		else:
			print(add_info)
	elif cmd == "ERR":
		print("Error message received.\n")
	else:
		print("Recieved an unknown command.\n")


def process_msg(rcv):
	if verify_signature(rcv, load_ECC_key(server_pubsigkeyfile)):
		msg = decrypt_with_RSA(rcv, key_pair)
		version = msg[0:2]
		msg_sqn = msg[2:4]
		cmd = msg[4:7]
		add_info = msg[7:263]                               ## IDK if this is right
		file = msg[263:]								    ## IDK if this is right
		if handle_seq_num(msg_sqn) > 0:
			process_cmd(cmd, add_info, file)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
while True:
	cmd_line = input('Type a command: ')
	cmd, add_info, filename = parse_cmd_line(cmd_line)
	if is_valid_cmd(cmd):
		payload = ''
		if filename != '':
			payload = encrypt_file(filename)
		msg = construct_msg(get_ver_num(), local_seq_num, cmd, load_RSA_key(server_pubenckeyfile), add_info, payload)
		local_seq_num += 1
		netif.send_msg(SERVER_ADDR, msg)
	status, rcv = netif.receive_msg(blocking=False)
	process_msg(rcv)
