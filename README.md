Setup
-----

The directory structure is already set up in the repository, but we explain regardless in case you would like to simulate additional users.

In the same directory as client.py, server.py, and the network module files, there should be a directory titled network/ for use by the network module, as well as a directory titled server/, and directories named with the user IDs of each user.

The directories named after user IDs simulate the local storage of each user, and should contain the private RSA encryption, ECC signature keys, and AES encryption keys, as well as the public encryption and signature keys for the server. If you would like to add additional users, new keys need to be generated, and you can check the format of these files if you would like to add new ones.

The server directory should contain subdirectories for each user for their files, as well as one for each user's keys.

*NOTE:* In client.py, there is a global variable named "network_delay". This value must be larger than the time (in seconds) it takes the server to send a message to the client. It's default value is ~2 seconds. If you are experiencing issues when attempting to run the code (such as sequence number errors), try increasing this value by half-second increments until the issues are resolved. 

Usage
-----

To run the network module, use 'python network.py -p ./network/ -a AB --clean'

To run the server, use 'python server.py'

To run the client, use 'python client.py XXX' where XXX is the ID the user. We add this feature so that client.py can simulate being run as different users on different machines.

Once all three python programs have been run in this order, you can login as a user by typing 'LGN XXX' where XXX is the user ID (example: 'LGN 789').
