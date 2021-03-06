import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

NET_PATH = './network/'
OWN_ADDR = 'B'
SERVER_ADDR='A'
MY_DIR = sys.argv[1]
my_privenckey = load_RSA_key(MY_DIR + '/privenc.pem')
my_privsigkey = load_ECC_key(MY_DIR + '/privsig.pem')
server_pubenckey = load_RSA_key(MY_DIR + '/server/pubenc.pem')
server_pubsigkey = load_ECC_key(MY_DIR + '/server/pubsig.pem')
from_server_seq_num = -1
local_seq_num = 1
# this value must be larger than the amount of time it takes to receive a
# network message if having difficulties increase this value by 0.5
network_delay = 2

def get_aes_key(filename):
	with open(filename, 'rt') as sf:
		return bytes.fromhex(sf.readline()[len("key: "):len("key: ")+32])

my_privaeskey  = get_aes_key(MY_DIR + '/privaes.txt')

def encrypt_file(filename):
	"""
	Encrypted the file under the given filename with GCM encryption.
	"""
	try:
		inf = open(filename, 'r')
	except:
		print('File does not exist.')
		return -1, -1
	payload = inf.read()
	payload = payload.encode('ascii')
	cipher = AES.new(my_privaeskey, AES.MODE_GCM)
	ciphertext, auth_tag = cipher.encrypt_and_digest(payload)
	nonce = cipher.nonce
	return auth_tag, nonce + ciphertext

def decrypt_file(filename, auth_tag, bytestring):
	"""
	Decrypt the given bytes using GCM and save to the given filename.
	"""
	received_nonce = bytestring[:16]
	ciphertext = bytestring[16:]
	cipher = AES.new(my_privaeskey, AES.MODE_GCM, received_nonce)
	plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
	f = open(filename, 'w')
	f.write(plaintext.decode('ascii'))

def send_oos_msg(seq_num=-1):
	"""Sends and OOS message to the server.
	To have a blank OOS command, use seq_num=-2, otherwise seq_num will be added to parameter field.
	"""
	if seq_num == -2:
		msg = construct_msg(get_ver_num(), local_seq_num, 'OOS', server_pubenckey, my_privsigkey)
	else:
		seq_num_byte = seq_num.to_bytes(length=185, byteorder='big')
		msg = construct_msg(get_ver_num(), local_seq_num, 'OOS', server_pubenckey, my_privsigkey, str(seq_num))
	netif.send_msg(SERVER_ADDR, msg)

def handle_seq_num(received_seq_num):
	if received_seq_num == from_server_seq_num + 1:
		return 1
	elif received_seq_num <= from_server_seq_num:
		send_oos_msg(seq_num=-2)
		print("Sequence number too low - sent OOS")
		return -1
	else:
		send_oos_msg(seq_num=received_seq_num)
		print("Sequence number too high - sent OOS")
		return -1

def process_cmd(cmd, add_info, auth_tag, file):
	global from_server_seq_num, local_seq_num
	cmd = cmd.decode('ascii')
	if cmd == 'SCS': # on login success
		local_seq_num = 1
		print('Login success... wait to be prompted for command.')
	elif cmd == 'SUC':
		pass
	elif cmd == 'REP':
		if file != b'' and auth_tag != b'':
			decrypt_file(add_info, auth_tag, file)
			print('Saved file ' + add_info.decode('ascii') + ' to your local drive.')
		else:
			print(add_info.decode('ascii'))
	elif cmd == 'RES':
		print(add_info.decode('ascii'))
	elif cmd == 'ERR':
		print('Error message received - ', add_info)
	elif cmd == 'RLO':
		print('Logged out.')
		from_server_seq_num = -1
		local_seq_num = 1
	elif cmd == 'OOS':
		if add_info != '':
			from_server_seq_num = int.from_bytes(add_info, byteorder='big')
			print('OOS - expected client sequence number set to ' + str(from_server_seq_num))
		else:
			print('OOS without sequence number changed received.')
	else:
		print('Recieved an unknown command.')

def process_msg(rcv):
	global from_server_seq_num
	if verify_signature(rcv, server_pubsigkey):
		ver, enc_payload, auth_tag, file, sig = parse_received_msg(rcv)
		msg = decrypt_with_RSA(enc_payload, my_privenckey)
		received_seq_num = int.from_bytes(msg[:2], byteorder='big')
		if handle_seq_num(received_seq_num) > 0:
			cmd = msg[2:5]
			add_info = msg[5:190]
			from_server_seq_num += 1
			process_cmd(cmd, add_info, auth_tag, file)

netif = network_interface(NET_PATH, OWN_ADDR)
while True:
	cmd_line = input('Type a command: ')
	parsed = parse_cmd_line(cmd_line)
	if parsed == None:
		print('Malformatted command line. Check the command.')
	else:
		cmd = parsed[0]
		if is_valid_cmd(cmd):
			msg = None
			if len(parsed) > 1:
				if cmd == 'LGN':
					if parsed[1] != MY_DIR:
						print('You did not send the right user ID with the login.')
					msg = construct_msg(get_ver_num(), local_seq_num, cmd, server_pubenckey, my_privsigkey, parsed[1])
				elif cmd == 'UPL':
					auth_tag, enc_file = encrypt_file(parsed[1])
					if auth_tag != -1:
						msg = construct_msg(get_ver_num(), local_seq_num, cmd, server_pubenckey, my_privsigkey, parsed[1], enc_file, auth_tag)
				else:
					msg = construct_msg(get_ver_num(), local_seq_num, cmd, server_pubenckey, my_privsigkey, parsed[1])
			else:
				if cmd == 'LGO':
					msg = construct_msg(get_ver_num(), local_seq_num, cmd, server_pubenckey, my_privsigkey)
				else:
					msg = construct_msg(get_ver_num(), local_seq_num, cmd, server_pubenckey, my_privsigkey)
			if msg != None:
				local_seq_num += 1
				netif.send_msg(SERVER_ADDR, msg)
		rcv = True
		while rcv:
			time.sleep(network_delay)
			status, rcv = netif.receive_msg(blocking = False)
			if (status):
				process_msg(rcv)
