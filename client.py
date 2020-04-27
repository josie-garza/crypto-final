import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA

NET_PATH = './network/'
OWN_ADDR = 'B'
my_pubenckeyfile = './network/A/pubenc.pem'
my_pubsigkeyfile = './network/A/pubsig.pem'
my_privenckeyfile = 'client_priv.pem'
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
print('Done.')

def send_login():
	print('Sending login message.')
	msg = construct_msg(version, local_seq_num, 'LGN', load_publickey(server_pubenckeyfile))
	netif.send_msg('A', msg)

def send_logout():
	print('Sending logout message.')
	msg = construct_msg(version, local_seq_num, 'LGO', load_publickey(server_pubenckeyfile))
	netif.send_msg('A', msg)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
while True:
	msg = input('Type a command: ')
	if msg == 'login':
		send_login()
	if msg == 'logout':
		send_logout()
	status, msg = netif.receive_msg(blocking=True)
