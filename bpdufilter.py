#!/usr/bin/python3

import getpass
import sys
import time
import paramiko
import telnetlib
import re

def read_switch_ip_list(path):
#	Function to read hosts IP addresses from file
	try:
		hosts_file = open(path, "r")
		hosts_list = hosts_file.readlines()
		hosts_file.close()
		#	Strip EOL symbols
		for i in range(0, len(hosts_list)):
			hosts_list[i]=hosts_list[i].rstrip()
		return hosts_list
	except:
		print('Error opening hosts file')
		return('ERROR')

def wipe_results_file(path):
#	Function to wipe results file
	results_file = open(path, "w")
	results_file.close()

def try_telnet(ip):
	host_telnet_object = telnetlib.Telnet()
	try:
		host_telnet_object.open(ip, 23, timeout=3)
		host_telnet_object.read_very_lazy()
		host_telnet_object.close()
		return 'OK'
	except:
		return 'FAILED'



def telnet_open_connection(ip):
	host_telnet_object = telnetlib.Telnet()
	host_telnet_object.open(ip, 23, timeout=3)
	return(host_telnet_object)

def telnet_send_username_password(host_telnet_object, usr, passwd, old_session=''):
# try to connect using username and password
# return:
# Telnet Session Output if correct prompt was received
# 'SIMPLE PASSWORD' if device asked for just password
# 'FAILED' if the prompt was wrong

# An old session output may optionally be passed to the function
# This is to be able to work with previously existing session
# and try another username and password within

	if old_session == '':
		try:
			session = host_telnet_object.read_until(b"Username: ", timeout=5)
		except Exception as e:
			return(str(e))
	else:
		session = old_session
		
	if "Username:" in str(session) and not "Screen" in str(session):
		print('*** Received username prompt. Trying username and password.')	
		try:
			host_telnet_object.write(usr.encode('ascii') + b"\n")
			time.sleep(1)
			host_telnet_object.read_until(b'Password: ', 5)
			host_telnet_object.write(passwd.encode('ascii') + b"\n")
			time.sleep(4)
			print('*** Checking answer from the device.')
			session = host_telnet_object.read_very_eager()
			return(session)
		except Exception as e:
			return(str(e))
	elif "Password:" in str(session) and not "Username:" in str(session):
		print('*** No username configured, only password.')
		return('SIMPLE PASSWORD')
	else:
		print('*** No correct prompt received')
		return('NO PROMPT')

def telnet_send_simple_password(host_telnet_object, passwd):
# try to connect simple password
# return session output
	host_telnet_object.write(passwd.encode('ascii') + b'\n')
	time.sleep(3)
	session = host_telnet_object.read_very_eager()
	return(session)

def telnet_access_priv_mode(host_telnet_object, passwd):
	host_telnet_object.write(b'enable\n')
	time.sleep(1)
	host_telnet_object.write(passwd.encode('ascii') + b'\n')
	time.sleep(1)
	session = host_telnet_object.read_very_eager()
	if '#' in str(session):
		print('*** Priv mode accessed')
		return(session)
	else:
		print('*** Failed to access priv mode')
		return('FAILED')

def telnet_send_command(host_telnet_object, cli_command):
	cli_command_bytes = bytes(cli_command, encoding='ASCII')
	host_telnet_object.write(cli_command_bytes + b'\n')
	time.sleep(2)
	return(host_telnet_object.read_very_eager())

def telnet_obtain_hostname(session):
#	Obtain switch hostname from session output
#	Returns string

#	Return all that comes after the last "Hostname" word
	hostname = str(session.decode('ascii')).split('hostname ')[-1]
#	Strip trailing switch prompt 
	hostname = hostname.split('\r\n')[0]
	return(hostname)

def telnet_obtain_model(session):
#	Obtain switch model from session output
#	Returns string


	model = str(session.decode('ascii'))
	reg_exp = re.compile('(?<=PID:)(.*)(?=\W+,\W+VID)')
	try:
		match_object = reg_exp.search(str(model))
		return(match_object.group().strip())
	except:
		return('FAILED TO RETRIEVE MODEL')
#	Strip leading and trailing spaces 
	model = model.strip()
	return(model)

def telnet_obtain_ios_ver(session):
#	Obtain switch IOS version from session output
#	Returns string

#	Return all that comes after the last "Hostname" word
	ios_ver = str(session.decode('ascii'))
#	Strip trailing switch prompt
	try:
		ios_ver = ios_ver.split('\r\n')[1]
	except:
		return('FAILED TO RETIREVE')
#	Wipe out all the commas
	ios_ver = ios_ver.replace(',','')
	return(ios_ver)

def telnet_obtain_image_name(session):
	reg_exp = re.compile('(?<=flash:)(.*)(?=")')
	match_object = reg_exp.search(str(session))
	try:
		return(match_object.group())
	except:
		return('FAILED TO RETRIEVE')

def telnet_get_interface_list(session):
	sh_ip_int_brief = session.decode('ascii')
	reg_exp = re.compile('\w+Ethernet\d+[/\d*]*')
	interface_list = re.findall(reg_exp,str(sh_ip_int_brief))
	return(interface_list)
	

switch_ip_file = 'trylist.txt'
result_file = 'bpdufilter_result.txt'
separator = ';'
result_list = list()

# Prompt for usernames and passwords
# RADIUS credentials:
print('Enter RADIUS username')
radius_username = input('Username: ')
print('Enter RADIUS password (username:' + radius_username + ')')
radius_password = getpass.getpass()
# Local switch credentials to try if RADIUS credentials fail:
print('Enter LOCAL username')
local_username = input('Username: ')
print('Enter LOCAL password: (username:' + local_username + ')')
local_password = getpass.getpass()
# Password to access priv mode
print('Enter ENABLE password')
enable_password = getpass.getpass()
# Simple password, for switches that don't have user accounts configured
print('Enter SIMPLE password')
simple_password = getpass.getpass()

# Read IP address list
switch_ip_list = read_switch_ip_list(switch_ip_file)

print('*** Read switches list from file')
print(switch_ip_list)
print('*** Total number of hosts to check: ' + str(len(switch_ip_list)))

# Wipe results file
wipe_results_file(result_file)

# Start querying switches
for switch_ip in switch_ip_list:
	# Reset variables
	authenticated = False
	privmode = False
	radius_status = ''

	print('*** Checking if Telnet is enabled for ' + switch_ip)
	telnet_test_result = try_telnet(switch_ip)

	if telnet_test_result == 'OK':
#		Open connection again	
		current_host = telnet_open_connection(switch_ip)

#		First, try radius username and password
		current_session_output = telnet_send_username_password(current_host, radius_username, radius_password)
		print(str(current_session_output))


#		If device asked for just simple password, send it
		if str(current_session_output) == 'SIMPLE PASSWORD':
			print('*** Failed to authenticate with RADIUS account')
			print('*** Trying simple password')
			radius_status = 'FAILED'
			current_session_output = telnet_send_simple_password(current_host, simple_password)
			if '>' in str(current_session_output) or '#' in str(current_session_output):
				print('*** Authenticated with simple password')
				authenticated = True
			else:
				print('*** Failed to authenticate with simple password')
				authenticated = False

		elif str(current_session_output) == 'NO PROMPT':
#	 	If device did not give correct prompt for either user account
# 		or simple password - abandon it
			radius_status = 'FAILED'
			print('*** Failed to authenticate to with RADIUS account')
			print('*** No correct prompt received')
			authenticated = False
#			go to the next switch
			print('*** Moving on to the next switch')
			continue

		elif 'Username:' in str(current_session_output):
# 		If device prompted for username again, it means 
#		it didn't accept radius account, try to send
#		local username and password
			radius_status = 'FAILED'
			print('*** Failed to authenticate to with RADIUS account')
			print('*** Trying local account')
			current_session_output = telnet_send_username_password(current_host, local_username,local_password, current_session_output)

			if '>' in str(current_session_output) or '#' in str(current_session_output):
#			Authenticated with local credentials
				print('*** Authenticated with local user account')
				authenticated = True
			else:
#			Local credentials didn't work as well
				print('*** Failed to authenticate with local user account')
				authenticated = False
				continue
		elif '>' in str(current_session_output) or '#' in str(current_session_output):
#		Successfully authenticated via RADIUS
			radius_status = 'OK'
			print('*** Authenticated with RADIUS account')
			authenticated = True
	else:
#	Telnet connection failed
		print (telnet_test_result)
		print ('Failed to access tenlet')
		
		authenticated = False
		radius_status = 'FAILED'
		continue

	if authenticated and '>' in str(current_session_output):
#	If the session is authenticated but not in priv mode, try to access
#	 priv mode
		print('*** Currently in user mode. Trying to access priv mode')
		print(current_session_output.decode('ascii'))
		current_session_output = telnet_access_priv_mode(current_host, enable_password)


	elif authenticated and '#' in str(current_session_output):
#	If the session is already in private mode, 
		print(current_session_output.decode('ascii'))
		print('*** Already in priv mode. Ready to send-receive commands')
		privmode = True

	if not authenticated:
		print('*** Failed to access configuration')
		privmode = False
		continue
	elif authenticated:
		try:
			print(current_session_output.decode('ascii'))
		except Exception as e:
			print(e + '!!!')
		print('*** Accessed priv mode sucessfully. Ready to send-receive commands')
		privmode = True
#####################
#	CLI actions		#
#####################
	if authenticated and privmode:

		current_session_output = telnet_send_command(current_host, 'terminal length 0')
		print(current_session_output.decode('ascii'))

	# Get hostname
		current_session_output = telnet_send_command(current_host, 'show run | inc hostname')
		print(current_session_output.decode('ascii'))
		hostname_got = telnet_obtain_hostname(current_session_output)

	# Get sh ip int brief	
		current_session_output = telnet_send_command(current_host, 'show ip int brief\n')
		print(current_session_output.decode('ascii'))
		interface_list = telnet_get_interface_list(current_session_output)		
		print('Retrieved the following interfaces', interface_list)

		result_file_object = open(result_file, 'a')
		result_file_object.write('=================================\n')
		result_file_object.write('SWITCH: ' + hostname_got + '\n')
		result_file_object.write('IP: ' + switch_ip + '\n')
		result_file_object.write('=================================\n')
		


# Check if there is bpdufilter configured 
		for interface in interface_list:
			sh_run_int_command = 'show run int ' + interface
			sh_run_int = telnet_send_command(current_host, sh_run_int_command).decode('ascii')
			print(sh_run_int)
			sh_run_int = re.search('interface(?s)(.*)end', sh_run_int).group()
			
			
			if 'bpdufilter' in sh_run_int:
				result_file_object.write(sh_run_int + '\n\n')
				print(sh_run_int)
		
		result_file_object.write('\n=================================\n')
		result_file_object.close()

	else:
#	If something is wrong, move on to the next switch
		print('*** Moving on to the next switch')
#	Close connection if there is one opened
	try:
		current_host.close()
	except:
		print('*** No connections to close')

print('*** Job is Finished')
