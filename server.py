import os, sys, getopt, time
from netinterface import network_interface
from shared import *
from Crypto.PublicKey import RSA

NET_PATH = './network/'
OWN_ADDR = 'A'
USER_ADDR = 'B'
SERV_DIR = './server/'
current_dir = ''
my_pubenckey = load_RSA_key(SERV_DIR + 'keys/server/pubenc.pem')
my_pubsigkey = load_RSA_key(SERV_DIR + 'keys/server/pubsig.pem')
my_privenckey = load_RSA_key(SERV_DIR + 'keys/server/privenc.pem')
my_privsigkey = load_RSA_key(SERV_DIR + 'keys/server/privsig.pem')
client_pubenckey = ''
client_pubsigkey = ''
from_client_seq_num = 0
local_seq_num = 0
version = 0
current_user = ''

# ------------
# definitions
# ------------


def start_session(user_ID):  # TODO: debug
	"""Initializes the session by setting user-depended parameters."""
	global current_user, local_seq_num, from_client_seq_num, client_pubenckey, client_pubsigkey
	# set parameters
	current_user = user_ID
	local_seq_num, from_client_seq_num = 0, 0
	# get keys
	with open(SERV_DIR + 'keys/' + user_ID + '/pubenc.pem') as f:
		client_pubenckey = f.read()
	with open(SERV_DIR + 'keys/' + user_ID + '/pubsig.pem') as f:
		client_pubsigkey = f.read()
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
	global local_seq_num, from_client_seq_num, client_pubenckey, client_pubsigkey, current_user
	local_seq_num, from_client_seq_num = 0, 0
	client_pubenckey, client_pubsigkey, current_user = '', '', ''


def process_command(code, add_info='', file=b''):
	# TODO: debug
	# TODO: replace current file reading with 'with'
	"""Executes a received command."""
	global local_seq_num, current_dir, from_client_seq_num
	if code == 'MKD':
		if add_info == '':
			send_error_msg('no parameter given')
			print("MKD no parameter given error sent")
		else:
			syscode = os.system('mkdir ' + SERV_DIR + current_dir + add_info)
			if syscode != 0:
				send_error_msg('unable to make directory')
				print("MKD unable to make directory error sent")
			else:
				send_success()
				print("MKD success sent")
	elif code == 'RMD':
		if add_info == '':
			send_error_msg('no parameter given')
			print("RMD no parameter given error sent")
		else:
			syscode = os.system('rm -r ' + SERV_DIR + current_dir + add_info)
			if syscode != 0:
				send_error_msg('unable to remove directory')
				print("RMD unable to remove directory error sent")
			else:
				send_success()
				print("RMD success - directory removed")
	elif code == 'GWD':
		msg = construct_msg(version, local_seq_num, 'REP', client_pubenckey, add_info=current_dir)
		netif.send_msg(USER_ADDR, msg)
		local_seq_num += 1
		print("GWD response sent")
	elif code == 'CWD':
		directories = add_info.split('/')
		current_dir = change_dir(directories, current_dir)
		print("CWD success - directory changed")
	elif code == 'LST':  # TODO: is it an issue that this will break for long lists?
		directories = os.listdir(SERV_DIR + current_dir)
		output = ', '.join(directories)
		msg = construct_msg(version, local_seq_num, 'REP', client_pubenckey, add_info=output)
		netif.send_msg(USER_ADDR, msg)
		local_seq_num += 1
		print("LST response sent")
	elif code == 'UPL':
		if add_info == '':
			send_error_msg('no file name given')
			print("UPL no file name given error sent")
		elif file == '':
			send_error_msg('no file given')
			print("UPL no file given error sent")
		else:
			f = open(SERV_DIR + current_dir + add_info, 'wb')
			f.write(file)
			f.close()
			send_success()
			print("UPL success sent")
	elif code == 'DNL':
		if add_info == '':
			send_error_msg('no file name given')
			print("DNL no file name given error sent")
		elif add_info not in os.listdir(SERV_DIR + current_dir):
			send_error_msg('file with this name not found')
			print("DNL no file with given name error sent")
		else:
			f = open(SERV_DIR + current_dir + add_info, 'rb')
			file_contents = f.read()
			f.close()
			msg = construct_msg(version, local_seq_num, 'REP', client_pubenckey, file=file_contents)
			netif.send_msg(USER_ADDR, msg)
			local_seq_num += 1
			print("DNL response sent")
	elif code == 'RMF':
		if add_info == '':
			send_error_msg('no file name given')
			print("RMF no file name given error sent")
		elif add_info not in os.listdir(SERV_DIR + current_dir):
			send_error_msg('file does not exist')
			print("RMF file does not exist error sent")
		else:
			syscode = os.system('rm ' + SERV_DIR + current_dir + add_info)
			if syscode != 0:
				send_error_msg('unable to remove file')
				print("RMF unable to remove file error sent")
			else:
				send_success()
				print("RMF success sent")
	elif code == 'LGO':
		print("Logging user " + current_user + " out")
		logout()
	elif code == 'OOS':
		if add_info != '':
			from_client_seq_num = int(add_info)
			print("OOS - expected client sequence number set to " + str(from_client_seq_num))
		else:
			print("OOS without sequence number changed received")
	elif code == 'FMT':
		print("FMT error received")
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
	msg = construct_msg(version, local_seq_num, 'SUC', client_pubenckey)
	local_seq_num += 1
	netif.send_msg(USER_ADDR, msg)


def send_error_msg(code, seq_num=-1):  # TODO: debug
	"""Sends and error message to the client.

	Error messages are sent with the ERR command and a specification of the error as the parameter.
	Wrong sequence number error are sent with the OOS command.
	To have a blank OOS command, use seq_num=-2, otherwise seq_num will be added to parameter field.
	"""
	global local_seq_num
	if seq_num == -1:
		msg = construct_msg(version, local_seq_num, 'ERR', client_pubenckey)
	elif seq_num == -2:
		msg = construct_msg(version, local_seq_num, 'OOS', client_pubenckey)
	else:
		msg = construct_msg(version, local_seq_num, 'OOS', client_pubenckey, add_info=seq_num)
	netif.send_msg(USER_ADDR, msg)
	local_seq_num += 1


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
	if current_user == '':
		# login case
		print("Attempting login")
		directories = os.listdir(SERV_DIR + 'keys/')
		directories.remove('server')
		for dir in directories:
			# try all keys
			key = load_RSA_key(dir + '/pubsig.pem')
			if verify_signature(enc_msg, key):
				print("Correct key found")
				dec_msg = decrypt_with_RSA(enc_msg, key)
				_, current_user, _ = parse_cmd_line(dec_msg)
				client_pubenckey = load_RSA_key(dir + '/pubenc.pem')
				client_pubsigkey = key
				local_seq_num = 0
				from_client_seq_num = 0
				print("User " + current_user + " logged in")
	else:
		# normal case
		# verify signature
		if verify_signature(enc_msg, client_pubsigkey):
			# verify version number
			received_version = int.from_bytes(enc_msg[:2], byteorder='little')
			if version == received_version:
				dec_msg = decrypt_with_RSA(enc_msg[:263], my_privenckey)
				# check sequence number
				received_seq_num = int.from_bytes(dec_msg[:2], byteorder='big')
				if received_seq_num == from_client_seq_num + 1:
					cmd = dec_msg[2:5].decode('utf-8')
					parameter = dec_msg[5:261]
					if len(dec_msg) > 261:
						rec_file = dec_msg[261:]
					else:
						rec_file = ''
					process_command(cmd, parameter, rec_file)
				elif received_seq_num <= from_client_seq_num:
					send_error_msg('OOS')
					print("Sequence number too low - OOS returned")
				else:
					send_error_msg('OOS', received_seq_num)
					print("Sequence number too high - OOS returned")
			else:
				send_error_msg('wrong version number')
		else:
			send_error_msg('signature failed')
			print("Message received but signature verification failed (SIG returned)")
