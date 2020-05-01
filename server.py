import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA

NET_PATH = './network/'
OWN_ADDR = 'A'
USER_ADDR = 'B'
SERV_DIR = './server/'
current_dir = ''
my_pubenckeyfile = SERV_DIR + 'keys/server/pubenc.pem'
my_pubsigkeyfile = SERV_DIR + 'keys/server/pubsig.pem'
my_privenckeyfile = SERV_DIR + 'keys/server/privenc.pem'
my_privsigkeyfile = SERV_DIR + 'keys/server/privsig.pem'
client_pubenckeyfile = ''
client_pubsigkeyfile = ''
from_client_seq_num = 0
local_seq_num = 0
version = 0
current_user = ''

# ------------
# definitions
# ------------


def start_session(user_ID):  # TODO: debug
	"""Initializes the session by setting user-depended parameters."""
	global current_user, local_seq_num, from_client_seq_num, client_pubenckeyfile, client_pubsigkeyfile
	# set parameters
	current_user = user_ID
	local_seq_num, from_client_seq_num = 0, 0
	# get keys
	with open(SERV_DIR + 'keys/' + user_ID + '/pubenc.pem') as f:
		client_pubenckeyfile = f.read()
	with open(SERV_DIR + 'keys/' + user_ID + '/pubsig.pem') as f:
		client_pubsigkeyfile = f.read()
	# navigate to current user's directory
	current_dir = current_user + '/'


def login():
	"""Returns true if login is successful."""
	if current_user != '':
		return False
	else:
		pass  # TODO


def logout():
	"""Resets all user login info."""
	global local_seq_num, from_client_seq_num, client_pubenckeyfile, client_pubsigkeyfile, current_user
	local_seq_num, from_client_seq_num = 0, 0
	client_pubenckeyfile, client_pubsigkeyfile, current_user = '', '', ''


def process_command(code, add_info='', file=b''):
	# TODO: debug
	# TODO: replace current file reading with 'with'
	"""Executes a received command."""
	global local_seq_num, current_dir
	if code == 'MKD':
		if add_info == '':
			send_error_msg('no parameter given')
		else:
			syscode = os.system('mkdir ' + SERV_DIR + current_dir + add_info)
			if syscode != 0:
				send_error_msg('unable to make directory')
			else:
				send_success()
	elif code == 'RMD':
		if add_info == '':
			send_error_msg('no parameter given')
		else:
			syscode = os.system('rm -r ' + SERV_DIR + current_dir + add_info)
			if syscode != 0:
				send_error_msg('unable to remove directory')
			else:
				send_success()
	elif code == 'GWD':
		msg = construct_msg(version, local_seq_num, 'REP', client_pubenckeyfile, add_info=current_dir)
		netif.send_msg(USER_ADDR, msg)
		local_seq_num += 1
	elif code == 'CWD':
		directories = add_info.split('/')
		current_dir = change_dir(directories, current_dir)
	elif code == 'LST':  # TODO: is it an issue that this will break for long lists?
		directories = os.listdir(SERV_DIR + current_dir)
		output = ', '.join(directories)
		msg = construct_msg(version, local_seq_num, 'REP', client_pubenckeyfile, add_info=output)
		netif.send_msg(USER_ADDR, msg)
		local_seq_num += 1
	elif code == 'UPL':
		if add_info == '':
			send_error_msg('no file name given')
		elif file == '':
			send_error_msg('no file given')
		else:
			f = open(SERV_DIR + current_dir + add_info, 'wb')
			f.write(file)
			f.close()
			send_success()
	elif code == 'DNL':
		if add_info == '':
			send_error_msg('no file name given')
		elif add_info not in os.listdir(SERV_DIR + current_dir):
			send_error_msg('file with this name not found')
		else:
			f = open(SERV_DIR + current_dir + add_info, 'rb')
			file_contents = f.read()
			f.close()
			msg = construct_msg(version, local_seq_num, 'REP', client_pubenckeyfile, file=file_contents)
			netif.send_msg(USER_ADDR, msg)
	elif code == 'RMF':
		if add_info == '':
			send_error_msg('no file name given')
		elif add_info not in os.listdir(SERV_DIR + current_dir):
			send_error_msg('file does not exist')
		else:
			syscode = os.system('rm ' + SERV_DIR + current_dir + add_info)
			if syscode != 0:
				send_error_msg('unable to remove file')
			else:
				send_success()
	elif code == 'LGO':
		logout()
	else:
		send_error_msg('invalid command')


def change_dir(directories, old_dir):  # TODO: debug
	"""Returns the newly changed directory, or the old one if an error is encountered.

	change -- a list of the directories in the command (e.g. ['..', 'dir'] )
	"""
	new_dir = old_dir
	while len(directories) > 0 and directories[0] != '':
		if directories[0] == '..':
			if new_dir == '' or new_dir == '/':
				send_error_msg('at topmost directory')
				return current_dir
			else:
				path = new_dir.split('/')
				del path[-2]
				new_dir = '/'.join(path)
				del directories[0]
		else:
			new_dir = new_dir + directories[0] + '/'
	return new_dir


def send_success():  # TODO: debug
	"""Sends a success message to the client."""
	global local_seq_num
	msg = construct_msg(version, local_seq_num, 'SUC', client_pubenckeyfile)
	local_seq_num += 1
	netif.send_msg(USER_ADDR, msg)


def send_error_msg(code, seq_num=-1):  # TODO: debug
	"""Sends and error message to the client.

	Error messages are sent with the ERR command and a specification of the error as the parameter.
	Wrong sequence number error are sent with the OOS command.
	To have a blank OOS command, use seq_num=-2, otherwise seq_num will be added to parameter field.
	"""
	if seq_num == -1:
		msg = construct_msg(version, local_seq_num, 'ERR', client_pubenckeyfile)
	elif seq_num == -2:
		msg = construct_msg(version, local_seq_num, 'OOS', client_pubenckeyfile)
	else:
		msg = construct_msg(version, local_seq_num, 'OOS', client_pubenckeyfile, add_info=seq_num)
	netif.send_msg(USER_ADDR, msg)


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

""" test code
print('Generating a new 2048-bit RSA key pair for server...')
keypair = RSA.generate(2048)
save_publickey(keypair.publickey(), my_pubenckeyfile)
save_keypair(keypair, my_privenckeyfile)
print('Done.')
"""

# initialize
netif = network_interface(NET_PATH, OWN_ADDR)
print('Server waiting to receive messages...')

# main loop
while True:  # TODO: debug
	status, enc_msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
	# print(msg.decode('utf-8'))  # debugging
	# TODO: check signature
	dec_msg = decrypt_with_RSA(client_msg, my_privenckeyfile)
	cmd_line = parse_cmd_line(dec_msg)
	# login
	if current_user == '':
		# TODO: try all the keys
		if code == 'LGN':
			if login():
				construct_msg(version, local_seq_num, 'SCS', client_pubenckeyfile)
	# all other commands
