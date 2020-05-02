import getopt
import os
import sys

from netinterface import network_interface
from shared import *

NET_PATH = './network/'
OWN_ADDR = 'A'
USER_ADDR = 'B'
SERV_DIR = './server/'
user_dir = ''
current_dir = ''
my_pubenckey = load_RSA_key(SERV_DIR + 'keys/server/pubenc.pem')
my_pubsigkey = load_ECC_key(SERV_DIR + 'keys/server/pubsig.pem')
my_privenckey = load_RSA_key(SERV_DIR + 'keys/server/privenc.pem')
my_privsigkey = load_ECC_key(SERV_DIR + 'keys/server/privsig.pem')
client_pubenckey = ''
client_pubsigkey = ''
from_client_seq_num = 0
local_seq_num = 0
version = 0
current_user = ''


# ------------
# definitions
# ------------


# unused
# def start_session(user_id):
# 	"""Initializes the session by setting user-depended parameters."""
# 	global current_user, current_dir, local_seq_num, from_client_seq_num, client_pubenckey, client_pubsigkey
# 	# set parameters
# 	current_user = user_id
# 	local_seq_num, from_client_seq_num = 0, 0
# 	# get keys
# 	with open(SERV_DIR + 'keys/' + user_id + '/pubenc.pem') as f:
# 		client_pubenckey = f.read()
# 	with open(SERV_DIR + 'keys/' + user_id + '/pubsig.pem') as f:
# 		client_pubsigkey = f.read()
# 	# navigate to current user's directory
# 	current_dir = current_user + '/'


def logout():
    """Resets all user login info."""
    global local_seq_num, from_client_seq_num, client_pubenckey, client_pubsigkey, current_user, current_dir
    local_seq_num, from_client_seq_num = 0, 0
    client_pubenckey, client_pubsigkey, current_user, current_dir, user_dir = '', '', '', '', ''


def process_command(code_b, add_info='', file=b''):
    """Executes a received command."""
    global current_dir, from_client_seq_num
    code = code_b.decode('ascii')
    add_info = add_info.decode('ascii')
    if code_b in ['MKD', 'RMD', 'UPL', 'DNL', 'RMF'] and '..' in add_info:
        send_error_msg('Use CWD with .. before executing this command.')
        print(".. used in inappropriate message")
    elif code == 'MKD':
        if add_info == '':
            send_error_msg('no parameter given')
            print("MKD no parameter given error sent")
        else:
            try:
                os.mkdir(user_dir + current_dir + add_info)
                send('SUC')
                print("MKD success sent")
            except FileExistsError:
                send_error_msg('unable to make directory')
                print("MKDIR - unable to make directory error")
    elif code == 'RMD':
        if add_info == '':
            send_error_msg('no parameter given')
            print("RMD no parameter given error sent")
        else:
            try:
                os.rmdir(user_dir + current_dir + add_info)
                send('SUC')
                print("RMD success - directory removed")
            except FileNotFoundError:
                send_error_msg('unable to remove directory - does not exist')
                print("RMD - file not found error")
            except OSError:
                send_error_msg('unable to remove directory - not empty')
                print("RMD - directory not empty error")
    elif code == 'GWD':
        send('REP', current_dir)
        print("GWD response sent")
    elif code == 'CWD':
        directs = add_info.split('/')
        current_dir = change_dir(directs, current_dir)
        send('REP', 'Changed current directory to ' + current_dir)
        print("CWD success - directory changed")
    elif code == 'LST':  # TODO: is it an issue that this will break for long lists?
        directs = os.listdir(user_dir + current_dir)
        output = ', '.join(directs)
        send('REP', output.encode('utf-8'))
        print("LST response sent")
    elif code == 'UPL':
        if add_info == '':
            send_error_msg('no file name given')
            print("UPL no file name given error sent")
        elif file == '':
            send_error_msg('no file given')
            print("UPL no file given error sent")
        else:
            with open(user_dir + current_dir + add_info, 'wb') as f:
                f.write(file)
            send('SUC')
            print("UPL success sent")
    elif code == 'DNL':
        if add_info == '':
            send_error_msg('no file name given')
            print("DNL no file name given error sent")
        elif add_info not in os.listdir(user_dir + current_dir):
            send_error_msg('file with this name not found')
            print("DNL no file with given name error sent")
        else:
            f = open(user_dir + current_dir + add_info, 'rb')
            file_contents = f.read()
            f.close()
            send('REP', add_info.encode('utf-8'), file_contents)
            print("DNL response sent")
    elif code == 'RMF':
        if add_info == '':
            send_error_msg('no file name given')
            print("RMF no file name given error sent")
        try:
            os.remove(user_dir + current_dir + add_info)
            send('SUC')
            print("RMF success sent")
        except IsADirectoryError:
            send_error_msg('cannot delete directory with RMF')
            print("RMF - directory specified error")
        except FileNotFoundError:
            send_error_msg('file not found')
            print("RMF - file not found error")
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
    from_client_seq_num += 1


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
            del directories[0]
    return new_dir


def send_error_msg(specification='', seq_num=-1):
    """Sends and error message to the client.

    Error messages are sent with the ERR command and a specification of the error as the parameter.
    Wrong sequence number error are sent with the OOS command.
    To have a blank OOS command, use seq_num=-2, otherwise seq_num will be added to parameter field.
    """
    if seq_num == -1:
        spec_bytes = specification.encode('utf-8')
        send('ERR', spec_bytes)
    elif seq_num == -2:
        send('OOS')
    else:
        seq_num_byte = seq_num.to_bytes(length=185, byteorder='big')
        send('OOS', str(seq_num))


def send(code, param='', dnl_file=b''):
    global local_seq_num
    if dnl_file != b'':
        authentication = dnl_file[-16:]
    else:
        authentication = b''
    new_msg = construct_msg(version, local_seq_num, code, client_pubenckey, my_privsigkey, add_info=param,
                            enc_file=dnl_file, file_auth=authentication)
    local_seq_num += 1
    netif.send_msg(USER_ADDR, new_msg)
    print('Sent message to client....')
#print(str(version) + str(local_seq_num) + code + str(param) + str(dnl_file) + str(authentication))


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

# initialize
netif = network_interface(NET_PATH, OWN_ADDR)
print('Server waiting to receive messages...')

# main loop
while True:  # TODO: debug
    status, enc_msg = netif.receive_msg(blocking=True)
    print('Received a message....')
    received_version, payload, auth_tag, received_file, _ = parse_received_msg(enc_msg)
    if version != int.from_bytes(received_version, byteorder='big'):
        send_error_msg('wrong version number')
        print("Wrong version number received")
    else:
        if current_user == '':
            print("Attempting login")
            directories = os.listdir(SERV_DIR + 'keys/')
            directories.remove('server')
            for key_dir in directories:
                # try all keys
                key = load_ECC_key(SERV_DIR + 'keys/' + key_dir + '/pubsig.pem')
                if verify_signature(enc_msg, key):
                    client_pubenckey = load_RSA_key(SERV_DIR + 'keys/' + key_dir + '/pubenc.pem')
                    client_pubsigkey = key
                    print("Correct key found")
                    dec_msg = decrypt_with_RSA(payload, my_privenckey)
                    #_, current_user, _ = parse_cmd_line(dec_msg)
                    current_user = dec_msg[5:190]
                    current_user = current_user.decode('ascii')
                    user_dir = SERV_DIR + current_user + '/'
                    local_seq_num = 0
                    from_client_seq_num = 0
                    send('SCS')
                    print("User " + current_user + " logged in")
        else:
            # normal case
            # verify signature
            if verify_signature(enc_msg, client_pubsigkey):
                dec_msg = decrypt_with_RSA(payload, my_privenckey)
                # check sequence number
                received_seq_num = int.from_bytes(dec_msg[:2], byteorder='big')
                print(received_seq_num)
                print(from_client_seq_num)
                if received_seq_num == from_client_seq_num + 1:
                    #cmd, parameter = parse_cmd_line(dec_msg[2:])
                    cmd = dec_msg[2:5]
                    parameter = dec_msg[5:190]
                    process_command(cmd, parameter, received_file)
                elif received_seq_num <= from_client_seq_num:
                    send_error_msg(seq_num=-2)
                    print("Sequence number too low - OOS returned")
                else:
                    send_error_msg(seq_num=received_seq_num)
                    print("Sequence number too high - OOS returned")
            else:
                send_error_msg('signature failed')
                print("Message received but signature verification failed (SIG returned)")
