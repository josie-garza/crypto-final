import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA

NET_PATH = './network/'
OWN_ADDR = 'A'
my_pubenckeyfile = './network/B/pubenc.pem'
my_pubsigkeyfile = './network/B/pubsig.pem'
my_privenckeyfile = 'server_priv.pem'
client_pubenckeyfile = './network/A/pubenc.pem'
client_pubsigkeyfile = './network/A/pubsig.pem'
from_client_seq_num = 0
local_seq_num = 0
version = 0

# ------------
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python server.py')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python server.py')
		sys.exit(0)

print('Generating a new 2048-bit RSA key pair for server...')
keypair = RSA.generate(2048)
save_publickey(keypair.publickey(), my_pubenckeyfile)
save_keypair(keypair, my_privenckeyfile)
print('Done.')

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
print('Server waiting to receive messages...')
while True:
# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
	print(msg.decode('utf-8'))
