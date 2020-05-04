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


def logout():
    """Resets all user login info."""
    global local_seq_num, from_client_seq_num, client_pubenckey, client_pubsigkey, current_user, current_dir, user_dir
    send('RLO', 'Logged out.')
    local_seq_num, from_client_seq_num = 0, 0
    client_pubenckey, client_pubsigkey, current_user, current_dir, user_dir = '', '', '', '', ''


def process_command(code, add_info='', file=b''):
    """Executes a received command."""
    global current_dir, from_client_seq_num
    if code in ['MKD', 'RMD', 'UPL', 'DNL', 'RMF'] and '..' in add_info:
        send_error_msg('Use CWD with .. first to operate on outer folder.')
        print(".. used in inappropriate message")
    elif code in ['MKD', 'RMD', 'CWD', 'UPL', 'DNL', 'RMF'] and add_info == '':
        send_error_msg('no parameter given')
        print("no parameter given error sent")
    elif code == 'MKD':
        try:
            os.mkdir(user_dir + current_dir + add_info)
            send('SUC')
            print("MKD success sent")
        except FileExistsError:
            send_error_msg('unable to make directory')
            print("MKDIR - unable to make directory error")
    elif code == 'RMD':
        if all([i == '.' for i in add_info.split('/')]):
            send_error_msg('invalid syntax')
            print("RMD - invalid syntax")
        else:
            try:
                os.rmdir(user_dir + current_dir + add_info)
                send('SUC')
                print("RMD success - directory removed")
            except FileNotFoundError:
                send_error_msg('unable to remove directory - does not exist')
                print("RMD - file not found error")
            except OSError:
                send_error_msg('unable to remove directory - invalid directory syntax or directory not empty')
                print("RMD - directory not empty error")
    elif code == 'GWD':
        send('REP', 'home/' + current_dir)
        print("GWD response sent")
    elif code == 'CWD':
        directories = add_info.split('/')
        current_dir, success = change_dir(directories, current_dir)
        if success:
            send('REP', 'Changed current directory to home/' + current_dir)
            print("CWD success - directory changed")
    elif code == 'LST':
        directories = os.listdir(user_dir + current_dir)
        for d in directories:
            send('RES', d)
        print("LST response sent")
    elif code == 'UPL':
        if file == '':
            send_error_msg('no file given')
            print("UPL no file given error sent")
        else:
            try:
                with open(user_dir + current_dir + add_info, 'wb') as f:
                    f.write(file)
                send('SUC')
                print("UPL success sent")
            except FileNotFoundError:
                send_error_msg('path not found')
                print("UPL - path not found error")
    elif code == 'DNL':
        try:
            with open(user_dir + current_dir + add_info, 'rb') as f:
                file_contents = f.read()
            send('REP', add_info, file_contents)
            print("DNL response sent")
        except FileNotFoundError:
            send_error_msg('file not found')
            print("DNL - file not found error")
        except IsADirectoryError:
            send_error_msg('cannot download directory')
            print("DNL - is a directory error")
    elif code == 'RMF':
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


def change_dir(directories, old_dir):
    """Returns the newly changed directory, or the old one if an error is encountered.

    change -- a list of the directories in the command (e.g. ['..', 'dir'] )
    """
    new_dir = old_dir
    while len(directories) > 0 and directories[0] != '':
        if directories[0] == '..':
            if new_dir == '' or new_dir == '/':
                send_error_msg('at topmost directory')
                return current_dir, False
            else:
                path = new_dir.split('/')
                del path[-2]
                new_dir = '/'.join(path)
                del directories[0]
        else:
            lst = os.listdir(user_dir + current_dir)
            actual_dirs = [name for name in lst if os.path.isdir(user_dir + current_dir + name)]
            if directories[0] not in actual_dirs:
                send_error_msg('directory does not exist')
                print("CWD - directory does not exist error")
                return old_dir, False
            else:
                new_dir = new_dir + directories[0] + '/'
                del directories[0]
    return new_dir, True


def send_error_msg(specification='', seq_num=-1):
    """Sends and error message to the client.

    Error messages are sent with the ERR command and a specification of the error as the parameter.
    Wrong sequence number error are sent with the OOS command.
    To have a blank OOS command, use seq_num=-2, otherwise seq_num will be added to parameter field.
    """
    if seq_num == -1:
        send('ERR', specification)
    elif seq_num == -2:
        send('OOS')
    else:
        send('OOS', str(seq_num))


def send(code, param='', dnl_file=b''):
    global local_seq_num
    if dnl_file != b'':
        authentication = dnl_file[-16:]
        dnl_file = dnl_file[:-16]
    else:
        authentication = b''
    new_msg = construct_msg(version, local_seq_num, code, client_pubenckey, my_privsigkey, add_info=param,
                            enc_file=dnl_file, file_auth=authentication)
    local_seq_num += 1
    netif.send_msg(USER_ADDR, new_msg)
    print('Sent message to client....')
    print(str(version) + str(local_seq_num) + code + str(param) + str(dnl_file) + str(authentication))


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
            directs = os.listdir(SERV_DIR + 'keys/')
            directs.remove('server')
            for key_dir in directs:
                # try all keys
                key = load_ECC_key(SERV_DIR + 'keys/' + key_dir + '/pubsig.pem')
                if verify_signature(enc_msg, key):
                    client_pubenckey = load_RSA_key(SERV_DIR + 'keys/' + key_dir + '/pubenc.pem')
                    client_pubsigkey = key
                    print("Correct key found")
                    dec_msg = decrypt_with_RSA(payload, my_privenckey)
                    cmd = dec_msg[2:5].decode('ascii')
                    if cmd != 'LGN':
                        print("wrong login command")
                    else:
                        param_user = dec_msg[5:190].decode('ascii')
                        if param_user != key_dir:
                            print("wrong user specified")
                        else:
                            current_user = param_user
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
                print("received_seq_num: " + str(received_seq_num))
                print("from_client_seq_num " + str(from_client_seq_num + 1))
                if received_seq_num == from_client_seq_num + 1:
                    cmd_b = dec_msg[2:5]
                    cmd = cmd_b.decode('ascii')
                    parameter_b = dec_msg[5:190]
                    parameter = parameter_b.decode('ascii')
                    process_command(cmd, parameter, received_file + auth_tag)
                elif received_seq_num <= from_client_seq_num:
                    send_error_msg(seq_num=-2)
                    print("Sequence number too low - OOS returned")
                else:
                    send_error_msg(seq_num=received_seq_num)
                    print("Sequence number too high - OOS returned")
            else:
                send_error_msg('signature failed - potential interference from another network entity')
                print("Message received but signature verification failed")
