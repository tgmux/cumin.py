#! /usr/bin/python
import bcrypt
from cassandra.cluster import Cluster, NoHostAvailable
from cassandra import InvalidRequest
import ConfigParser
import getpass
from optparse import OptionParser
import os
import sys

# Connect to cassandra and return a session
def connectCassandra(hostname, username, password):
	# Simple function to return a dict with connection credentials
	def getCredential(self):
		return {'username':username, 'password':password}

	session = Cluster([hostname], auth_provider=getCredential).connect("system_auth")
	return session

# List users configured in a given cassandra host
def listCassandraUsers(session):
	# Run a few queries because cassandra doesn't support joins. 
	user_rows = session.execute('SELECT username, salted_hash FROM credentials')
	name_rows = session.execute('SELECT * FROM users')
	perm_rows = session.execute('SELECT * FROM permissions')

	users = []
	max_resource_length = 0
	max_username_length = 0
	# First, look for superusers
	for (name_name, superuser) in name_rows:
		if superuser == True:
			super_dict = {}
			super_dict['name'] = name_name
			super_dict['resource'] = ""
			super_dict['permissions'] = ""
			super_dict['superuser'] = True

			for (user_name, salted_hash) in user_rows:
				if name_name == user_name:
					super_dict['salted_hash'] = salted_hash

			if max_username_length < len(name_name):
				max_username_length = len(name_name)

			users.append(super_dict)

	# Now let's find normal users who have some sort of permissions
	for (perm_name, resource, permissions) in perm_rows:
		user_dict = {}
		user_dict['name'] = perm_name
		user_dict['resource'] = resource
		user_dict['permissions'] = permissions
		user_dict['superuser'] = False

		if max_resource_length < len(resource):
			max_resource_length = len(resource)

		if max_username_length < len(perm_name):
			max_username_length = len(perm_name)

		for (user_name, salted_hash) in user_rows:
			if perm_name == user_name:
				user_dict['salted_hash'] = salted_hash

		users.append(user_dict)

	# Iter over the array of dicts and display infos
	users_length = len(users)
	max_resource_length += 1
	max_username_length += 1
	print ("Users(" + str(users_length) + "):").ljust(max_username_length), "Rnd:", "Resource:".ljust(max_resource_length), "Permissions:"
	print "----------------------------------------------------------------------------"
	for i in range(users_length):
		user = users[i]

		# Only display permissions if the user isn't so super.
		permissions = ""
		resource = ""
		if (user['superuser'] == True):
			resource = "Superuser"
			permissions = "Superuser"
		else:
			if 'resource' in user:
				resource = user['resource']
			else:
				resource = "None"

			if 'permissions' in user:
				if user['permissions'] is None:
					perm_length = 0
				else:
					perm_length = len(user['permissions'])
			else:
				perm_length = 0

			# Decide what to display based on number of permissions assigned
			# - ALTER
			# - AUTHORIZE
			# - CREATE
			# - DROP
			# - MODIFY
			# - SELECT
			if perm_length == 6:
				permissions = "All"
			elif (perm_length == 1) and (user['permissions'][0] == "SELECT"):
				permissions = "Read-Only"
			elif perm_length == 0:
				permissions = ""
			else:
				for perm in range(perm_length):
					if len(permissions) > 0:
						permissions = permissions + ", " + user['permissions'][perm]
					else:
						permissions = user['permissions'][perm]

		# Display values. Should probably just return this data and handle it somewhere else later
		username = user['name']
		hash_rounds = user['salted_hash'][4:6]
		print username.ljust(max_username_length), hash_rounds.ljust(4), resource.ljust(max_resource_length), permissions
	return True

# Create a new cassandra user
def createCassandraUser(session, username, password):
	session.execute(
		"""
		CREATE USER %s WITH PASSWORD %s NOSUPERUSER
		""",
		(username, password)
	)

	passwdCassandraUser(session, username, password)
	return True

# Delete a cassandra user
def deleteCassandraUser(session, username):
	try:
		session.execute("DROP USER %s" %username)
		return True
	except InvalidRequest as e:
		print "Error:", e[0]
		sys.exit()
	except Exception as e:
		print "Unhandled exception executing DROP USER:", e[0]
		sys.exit()

def getPasswdInput(username):
	while True:
		first_password = getpass.getpass(prompt="Please enter password for user " + username + ": ")
		second_password = getpass.getpass(prompt="Please enter matching password: ")

		if first_password == second_password:
			return first_password
		else:
			print "ERROR: Passwords do not match."

# Change a cassandra user's password
def passwdCassandraUser(session, username, password):
	hashola = bcrypt.hashpw(password, bcrypt.gensalt(4))

	session.execute(
		"""
		INSERT INTO system_auth.credentials (username, salted_hash)
		VALUES (%s, %s)
		""",
		(username, hashola)
	)
	return True

# Revoke a user's rights
def revokeCassandraUser(session, resource, username):
	print "Revoking all permissions on %s from %s" % (resource, username)
	session.execute("REVOKE ALL PERMISSIONS ON KEYSPACE %s FROM %s" % (resource, username))
	return True

# Grant a user rights
def grantCassandraUser(session, resource, username, grants):
	grants_length = len(grants)
	# We can assume if the grants requested is only one element and it contains ALL:
	if grants_length == 1 and grants[0] == "ALL":
		print "Granting all privileges on %s to %s" % (resource, username)
		session.execute("GRANT ALL PERMISSIONS ON KEYSPACE %s TO %s" % (resource, username))

	# If the grants array len is larger than one, we can assume we're specifying multiple grants
	elif grants_length > 1:
		grants_message = "Granted "
		for grant in range(grants_length):
			if grant == 0:
				grants_message = grants_message + grants[grant]
			else:
				grants_message = grants_message + ", " + grants[grant]

			session.execute("GRANT %s ON KEYSPACE %s TO %s" % (grants[grant], resource, username))
		print grants_message + " on %s to %s." % (resource, username)

	# This is actually caught when this function is called, but we should protect ourselves here too
	else:
		sys.exit("\nFatal :: Please supply some grants with your grant option.\n")

	return True

def main():
	# Parse command line arguments
	parser = OptionParser()
	parser.add_option("--conf",			action="store",		 help="Path to config file",	dest="config_path", 		type="string")
	parser.add_option("-H", "--host",	action="store",		 help="Database Hostname",		dest="database_hostname", 	type="string")
	parser.add_option("-u", "--user",	action="store", 	 help="Username to manipulate",	dest="database_username", 	type="string")
	parser.add_option("-w", "--pw",		action="store", 	 help="Password to set",		dest="database_password", 	type="string")
	parser.add_option("-r", "--resource", action="store",	 help="Resource to grant", 		dest="database_resource",	type="string")
	# User options
	parser.add_option("-l", "--list",	action="store_true", help="List cassandra users",	dest="action_list_users")
	parser.add_option("-n", "--new",	action="store_true", help="Create a new user",		dest="action_create_user")
	parser.add_option("-d", "--delete", action="store_true", help="Delete an existing user", dest="action_delete_user")
	parser.add_option("-p", "--passwd", action="store_true", help="Change a user's password", dest="action_passwd_user")
	parser.add_option("-g", "--grant",	action="store_true", help="Modify user's grants",	dest="action_grant_user")
	# Permissions Options
	parser.add_option("--alter",		action="store_true", help="Alter permission", 		dest="permission_alter")
	parser.add_option("--create",		action="store_true", help="Create permission", 		dest="permission_create")
	parser.add_option("--authorize",	action="store_true", help="Authorize permission", 	dest="permission_authorize")
	parser.add_option("--drop",			action="store_true", help="Drop permission", 		dest="permission_drop")
	parser.add_option("--modify",		action="store_true", help="Modify permission", 		dest="permission_modify")
	parser.add_option("--select",		action="store_true", help="Select permission", 		dest="permission_select")
	parser.add_option("--all",			action="store_true", help="Grant all permissions", 	dest="permission_all")
	parser.add_option("--revoke",		action="store_true", help="Revoke all permissions", dest="permission_revoke")
	(options, args) = parser.parse_args()

	# Read our configuration file and set username / password
	config = ConfigParser.SafeConfigParser()
	if options.config_path is None:
		config.read('/etc/cumin.conf')
	else:
		config.read(options.config_path)
		
	cassandra_username = config.get('cassandra', 'username')
	cassandra_password = config.get('cassandra', 'password')

	# Determine which database we want and connect
	cassandra_database = True # Replace all this later
	if cassandra_database == True:
		try:
			session = connectCassandra(options.database_hostname, cassandra_username, cassandra_password)
		except NoHostAvailable as e:
			print "Error:", e[1][options.database_hostname]
			sys.exit()
		except Exception as e:
			print "Unhandled exception connecting to host", e[0]
			sys.exit()

	#####################################################################
	# List users
	if options.action_list_users == True:
		listCassandraUsers(session)
		sys.exit()

	#####################################################################
	# Create a user
	if options.action_create_user == True:
		if options.database_password is None:
			options.database_password = getpass.getpass(prompt="Enter password for user " + options.database_username + ":")

		createCassandraUser(session, options.database_username, options.database_password)
		sys.exit()

	#####################################################################
	# Delete a user
	if options.action_delete_user == True:
		if options.database_username is None:
			sys.exit("\nFatal :: Please supply a user to delete.\n")

		deleteCassandraUser(session, options.database_username)
		sys.exit()

	#####################################################################
	# Update user's password
	if options.action_passwd_user == True:
		if options.database_username is None:
			sys.exit("\nFatal :: Please supply a user of which to modify their password.\n")

		if options.database_password is None:
			#options.database_password = getpass.getpass(prompt='Enter password for user ' + options.database_username + ':')
			options.database_password = getPasswdInput(options.database_username)

		passwdCassandraUser(session, options.database_username, options.database_password)
		sys.exit()

	#####################################################################
	# Update user's grants
	if options.action_grant_user == True:
		# Required - A User
		if options.database_username is None:
			sys.exit("\nFatal :: Please suppply a user of which to adjust grants.\n")
		# Required - A Keyspace, Table, Resource of some kind. 
		if options.database_resource is None:
			sys.exit("\nFatal :: Please supply a keyspace of which to grant privileges.\n")

		# If we --revoke, just yank the perms. Else, do everything. 
		if options.permission_revoke == True:
			revokeCassandraUser(session, options.database_resource, options.database_username)
		else: 
			grants = []
			if options.permission_all == True:
				grants = ['ALL']
			else:
				if options.permission_alter == True:
					grants.append('ALTER')
				if options.permission_create == True:
					grants.append('CREATE')
				if options.permission_authorize == True:
					grants.append('AUTHORIZE')
				if options.permission_drop == True:
					grants.append('DROP')
				if options.permission_modify == True:
					grants.append('MODIFY')
				if options.permission_select == True:
					grants.append('SELECT')

			# Required - A grant, all grants, some grants, no grants?
			if len(grants) < 1:
				sys.exit("\nFatal :: Please supply at least one permission or revoke the user's grants.\n")

			#revokeCassandraUser(session, options.database_resource, options.database_username)
			grantCassandraUser(session, options.database_resource, options.database_username, grants)
		sys.exit()
	#####################################################################

if __name__ == '__main__':
	main()