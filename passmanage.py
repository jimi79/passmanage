#!/usr/bin/python3


# apt-get install python3-crypto


# todo : better error msg if exceeption while opening the file

import argparse
import base64
import binascii 
from Crypto.Cipher import XOR
import getpass
import json
from operator import itemgetter
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

	key, pwlist = list_load()
	context = params[0]
	login = params[1]
	password = generate_pw()
	
	# first check if it exists, then confirm ?
	ok=True

	try:
		idx = get_index(pwlist, context, login)
	except ValueError:
		idx = -1

	if (idx != -1):
		a = input('This entry already exists, override ? [y/N] ')
		if (a.lower() != 'y'):
			ok=False

	if ok:
		echo = "Enter password (%s) : " % password 
		while True:
			pwtemp = getpass.getpass(echo) 
			if (pwtemp == ""):
				break
			else:
				pass2 = getpass.getpass('Confirm : ')
				if (pwtemp == pass2):
					password = pwtemp
					break
				print("Password don't match, again") 

		item = {'context':context, 'login':login, 'password':password}

		if (idx != -1):
			pwlist[idx] = item
		else:
			pwlist.append(item)
		list_save(key, pwlist) 
	return None

def changepw(params):
	key, pwlist = list_load()
	key = get_db_pass(save = True)
	list_save(key, pwlist)


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
	if (command == 'changepw') or (command == ''):
		print("  %s changepw : change the db password." % (program_name())) 
	if (command == 'list') or (command == ''):
		print("  %s list : list all context/logins." % (program_name()))
	if (command == 'remove') or (command == ''):
		print("  %s remove <context> <login> : remove password for the given context and login." % (program_name()))
		print("    <context> is a regexp. If multiples match, return a list of matches and remove none")
	if (command == 'search') or (command == ''):
		print("  %s search <context> <login> : return a password." % (program_name()))
		print("    <context> is a regexp. If multiples match, return a list of matches without passwords") 
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

def get_index(pwlist, context, login):
	return get_keys(pwlist).index((context, login))

def get_keys(pwlist):
	return [(i['context'], i['login']) for i in pwlist] 

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

def list(params):
	key, pwlist = list_load() 
	for i in pwlist:
		print("Context %s, login %s" % (i['context'], i['login']))
		

def list_load(): # open the file and return the list 
	filename = get_db_filename()
	if os.path.exists(filename):
		key = get_db_pass(save = False) 
		with open(filename, 'r') as infile:
			cdatas = infile.read() 
		datas = decrypt(key, cdatas).decode('utf-8') 
		#return key, pickle.loads(datas)
		return key, json.loads(datas) 
	else:
		return None, []

def list_save(key, pwlist): # save the file 
	if key == None:
		key = get_db_pass(save = True) 
	pwlist = sorted(pwlist, key = itemgetter('context', 'login')) 
	datas = json.dumps(pwlist)
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

	key, pwlist = list_load()
	res = search_db(pwlist, reg_context, reg_login) 
	if (res != None):
		print('Context : %s' % pwlist[res]['context'])
		print('Login : %s' % pwlist[res]['login'])
		print('Password : %s' % pwlist[res]['password']) 
	return None

def search_db(pwlist, reg_context, reg_login): # return the index if only one found, None otherwise
	reg_context = '^' + reg_context + '$'
	if reg_login != None:
		reg_login = '^' + reg_login + '$'
	res = []
	idx = []
	cpt = 0
	keys = get_keys(pwlist)
	cpt = 0
	for i in pwlist:
		ok = False
		if (re.match(reg_context, i['context'])):
			if (reg_login == None):
				ok = True
			else:
				if (re.match(reg_login, i['login'])):
					ok = True
			if ok:
				res.append(i)
				idx.append(cpt) 
		cpt = cpt + 1 

	if len(res) == 0:
		print("No result found")
		return None

	if len(res) > 1:
		print("Multiples results found :")
		for i in res:
			print("Context %s, login %s" % (i['context'], i['login'])) 
		return None

	if len(res) == 1:
		return idx[0]
			
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

	key, pwlist = list_load()
	idx = search_db(pwlist, reg_context, reg_login) 
	if idx != None:
		a = input('Remove login %s from context %s ? [y/N] ' % (pwlist[idx]['login'], pwlist[idx]['context']))
		if (a.lower() == 'y'): 
			del pwlist[idx]
			print("Removed")
			list_save(key, pwlist) 
	return None

def parse_main(param):
	act_list = {
		'add': add,
		'changepw': changepw,
		'init': init,
		'list': list,
		'remove': remove,
		'search': search}
	if (param in act_list.keys()):
		return act_list[param]
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


try:
	main()
except KeyboardInterrupt:
	print("\nCancelled") # \n because questions are always after somethg, and user might mostly break during a question in that program
except:
	raise
