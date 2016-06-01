#!/usr/bin/python3


# apt-get install python3-crypto

# write in git : 
# rahhhhhhhhhhh, my key is my context, meaning i can have only one account per context.
# i need to change the key for an array of context and login
# pb : in json, array index can't be a tuple. so i need to not use json 
# other solution : contatenate context and value, but that means good by regexp

# i think save another way, with a tuple as an index, even if it's strange


import argparse
import base64
import binascii 
from Crypto.Cipher import XOR
import getpass
import json
import os.path
import pickle
import random
import re
import string
import sys

config = os.environ['HOME'] + '/.config/passmanage'
default_conf = os.environ['HOME'] + '/passwords'

def add(params):
# params should be a list
	if (len(params) != 2):
		display_usage(command = 'add')
		sys.exit(1) # exit right away
		return None 

	pwlist = list_load()
	context = params[0]
	login = params[1]
	password = generate_pw()
	
	# first check if it exists, then confirm ?
	ok=True
	if ((context, login) in pwlist.keys()):
		a = input('This entry already exists, override ? [y/N] ')
		if (a.lower() != 'y'):
			ok=False

	if ok:
		echo = "Enter password (%s) : " % password
		pwtemp = getpass.getpass(echo) 
		if (pwtemp != ""):
			password = pwtemp

		pwlist[(context, login)] = {"password": password} 
		list_save(pwlist) 
	return None

def decrypt(key, ciphertext):
  cipher = XOR.new(key)
  return cipher.decrypt(base64.b64decode(ciphertext))

def display_usage(**params):
	command = param('command', params)
	print("Usage :")
	if (command == 'init') or (command == ''):
		print("  %s init <file> : setup the crypted file to be used (%s default)" % (program_name(), default_conf))
	if (command == 'add') or (command == ''):
		print("  %s add <context> <login> : add a password for a given context and login." % (program_name()))
		print("    example : %s add context facebook foobar password_b4r" % (program_name()))
	if (command == 'search') or (command == ''):
		print("  %s search <context> <login> : return a password." % (program_name()))
		print("    <context> is a regexp. If multiples match, return a list of matches without passwords")
	if (command == 'remove') or (command == ''):
		print("  %s remove <context> <login> : remove password for the given context and login." % (program_name()))
		print("    <context> is a regexp. If multiples match, return a list of matches and remove none")
	# allow a -f for remove, maybe

def encrypt(key, plaintext):
  cipher = XOR.new(key)
  #return base64.b64encode(cipher.encrypt(plaintext.encode('utf-8'))).decode('utf-8')
  return base64.b64encode(cipher.encrypt(plaintext)).decode('utf-8')

def exists_db():
	return os.path.exists(get_db_filename())

def generate_pw():
	random.seed()
	count=random.randrange(8,12)
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(count))

def get_db_pass(**params):
# paramter will be load or save
	if params['save'] == True:
		pass1 = ''
		pass2 = ''
		while True:
			pass1 = getpass.getpass('Enter the password to crypt the db file : ')
			pass2 = getpass.getpass('Confirm : ')
			if (pass1 == pass2):
				break
			print("Password don't match, again")
		return pass1
	else: 
		return getpass.getpass('Enter the password to decrypt the db file : ')

def get_db_filename():
	if (os.path.exists(config)):
		with open(config, 'r') as infile:
			djson = infile.read() 
		datas = json.loads(djson)
		return datas['file']
	else:
		return default_conf

def init(params):
	if (len(params) != 1):
		display_usage(command = 'init')
		sys.exit(1) # exit right away
		return None
	else: 
		if (not(os.path.exists(os.path.dirname(config)))):
			os.makedirs(os.path.dirname(config))

		if (os.path.exists(default_conf)):
			with open(config, 'r') as infile:
				djson = infile.read() 
			datas = json.loads(djson)
		else:
			datas = {}

		datas['file'] = params[0]
		djson = json.dumps(datas) 
		with open(config, 'w') as outfile:
			outfile.write(djson) 
		return None 

def list_load(): # open the file and return the list 
	filename = get_db_filename()
	if os.path.exists(filename):
		key = get_db_pass(save = False) 
		with open(filename, 'r') as infile:
			cdatas = infile.read() 
		datas = decrypt(key, cdatas) 
		return pickle.loads(datas)
	else:
		return {} 

def list_save(pwlist): # save the file 
	key = get_db_pass(save = True)
	datas = pickle.dumps(pwlist)
	filename = get_db_filename()
	cdatas = encrypt(key, datas) 
	with open(filename, 'w') as outfile:
		outfile.write(cdatas) 
	return None 

def param(key, parlist):
	if key in parlist.keys():
		return parlist[key]
	else:
		return ''

def program_name():
	return os.path.basename(sys.argv[0])

def search(params): # params is a list of sys.argv 
	if (len(params) < 1):
		display_usage(command = 'search')
		sys.exit(1) # exit right away
		return None 
	reg_context = params[0]
	if len(params) > 1:
		reg_login = params[1]
	else:
		reg_login = None

	pwlist = list_load()
	res = search_db(pwlist, reg_context, reg_login) 
	if (res != None):
		print('Context : %s' % res[0])
		print('Login : %s' % res[1])
		print('Password : %s' % pwlist[res]['password']) 
	return None

def search_db(pwlist, reg_context, reg_login): # return the index if only one found, None otherwise
	res = []
	reskey = []
	for i in pwlist.keys():
		ok = True
		if (re.match(reg_context, i[0]) == None):
			ok = False
		else:
			if ((reg_login != None) and
			 	  (re.match(reg_login, i[1]) == None)):
				ok = False 
		if ok:
			res.append({'context': i[0], 'login': i[1], 'password': pwlist[i]['password']})
			reskey.append(i)

	if len(res) == 0:
		print("No result found")
		return None

	if len(res) > 1:
		print("Multiples results found :")
		for i in res:
			print("Context %s, login %s" % (i['context'], i['login'])) 
		return None

	if len(res) == 1:
		return reskey[0]
			
def remove(params):
	if (len(params) < 1):
		display_usage(command = 'remove')
		sys.exit(1) 
		return None 

	reg_context = params[0]
	if len(params) > 1:
		reg_login = params[1]
	else:
		reg_login = None

	pwlist = list_load()
	res = search_db(pwlist, reg_context, reg_login) 
	if res != None:
		a = input('Remove login %s from context %s ? [y/N] ' % (res[0], res[1]))
		if (a.lower() == 'y'): 
			del pwlist[res]
			print("Removed")
			list_save(pwlist) 
	return None

def parse_main(param):
	list = {
		'add': add,
		'init': init,
		'search': search,
		'remove': remove}
	if (param in list.keys()):
		return list[param]
	else:
		return None
	
# we pass a pointer to the function. Each function will parse its arguments 

def main():
	if len(sys.argv) < 2:
		display_usage()
		sys.exit(1)
	else:
		func = parse_main(sys.argv[1])
		if (func == None):
			display_usage()
			sys.exit(1)

		if (len(sys.argv) > 2):
			params = sys.argv[2:]
		else:
			params = []

		if (func in [search, remove]):
			db = get_db_filename()
			if not(os.path.exists(db)):
				print("Database %s absent. Try adding something first with %s add <context> <login>" % (db, program_name()))
				sys.exit(1)
				return None

		func(params) 

main()
