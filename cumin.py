#! /usr/bin/python
import bcrypt
from cassandra import InvalidRequest
from cassandra.cluster import Cluster, NoHostAvailable
import ConfigParser
import getpass
import os
import sys

# Helper output
def displayHelp():
	return """
Usage: cumin.py [action] hostname <username> <keyspace> <permissions...>

Actions (required):
- list
- create (username)
- delete (username)
- passwd (username)
- revoke (username, keyspace)
- grant  (username, keyspace, permissions...)

Permissions:
- all
- alter
- authorize
- create
- drop
- modify
- select

Environment Variables:
- CUMIN_CONF - Path to cumin.conf

Examples:
$ cumin.py create mycassandrahost bossman superuser
$ cumin.py create mycassandrahost normaluser
$ cumin.py passwd mycassandrahost normaluser
$ cumin.py grant mycassandrahost normaluser akeyspace select alter create
$ cumin.py revoke mycassandrahost normaluser akeyspace
$ cumin.py grant mycassandrahost normaluser akeyspace all
"""

# Connect to cassandra and return a session
def connectCassandra(hostname, username, password):
	# Simple function to return a dict with connection credentials because reasons
	def getCredential(self):
		return {'username':username, 'password':password}

	# Perform the actual connect and return our session
	try:
		session = Cluster([hostname], auth_provider=getCredential).connect("system_auth")
		return session
	except NoHostAvailable as e:
		sys.exit("Error: " + str(e[1][hostname]))
	except Exception as e:
		sys.exit("Error: Exception connecting to host: " + str(e[0]))

# List users configured in a given cassandra host
def listCassandraUsers(session):
	try:
		# Run a few queries because cassandra doesn't support joins. 
		user_rows = session.execute('SELECT username, salted_hash FROM credentials')
		name_rows = session.execute('SELECT * FROM users')
		perm_rows = session.execute('SELECT * FROM permissions')
	except Exception as e:
		sys.exit("Error: Exception attempting to query database for users: " + str(e[0]))

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

			# Add salted hash to the user dict
			for (user_name, salted_hash) in user_rows:
				if name_name == user_name:
					super_dict['salted_hash'] = salted_hash

			# Field lengths for formatting our faux table
			if max_username_length < len(name_name):
				max_username_length = len(name_name)

			# Now append the superuser dict to the users array
			users.append(super_dict)

	# Now let's find normal users who have some sort of permissions
	for (perm_name, resource, permissions) in perm_rows:
		user_dict = {}
		user_dict['name'] = perm_name
		user_dict['resource'] = resource
		user_dict['permissions'] = permissions
		user_dict['superuser'] = False

		# Field lengths for formatting our faux table
		if max_resource_length < len(resource):
			max_resource_length = len(resource)

		if max_username_length < len(perm_name):
			max_username_length = len(perm_name)

		# Add salted hash to the user dict
		for (user_name, salted_hash) in user_rows:
			if perm_name == user_name:
				user_dict['salted_hash'] = salted_hash

		if permissions:
			# Now append the user dict to the users array
			#print "Permissions: %s" % permissions
			users.append(user_dict)

	# Iter over the array of dicts and display infos
	users_length = len(users)
	max_resource_length += 1
	max_username_length += 1
	print ("!Users(" + str(users_length) + "):").ljust(max_username_length), "Rnd:", "Resource:".ljust(max_resource_length), "Permissions:"
	print "----------------------------------------------------------------------------"
	for i in range(users_length):
		user = users[i]
		permissions = ""
		resource = ""

		# If we have superuser privs, there's no point in checking anything else. 
		if (user['superuser'] == True):
			resource = "Superuser"
			permissions = "Superuser"
		# Only display permissions if the user isn't so super.
		else:
			if 'resource' in user:
				resource = user['resource']
			else:
				resource = "None"

			# Figure out how many separate permissions the user is assigned
			#	we can make some assumptions based on this number and give 
			#	them a friendly name like "Read-Only" or "All".
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
				# Display a readable list of all the permissions
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
#
# Create a new cassandra user
def createCassandraUser(session, username, superuser):
	# Handle creation of superusers versus normal users
	su = "NOSUPERUSER"
	if superuser == True:
		su = "SUPERUSER"

	password = getPasswdInput(username)
	try:
		# After user is created, set their password so we can knock down the bcrypt rounds from 10
		session.execute("CREATE USER %s WITH PASSWORD \'%s\' %s" % (username, password, su))
		print "User %s created successfully" % username

		passwdCassandraUser(session, username, password)
		return True
	except Exception as e:
		sys.exit("Exception executing CREATE USER:" + str(e))
#
# Delete a cassandra user
def deleteCassandraUser(session, username):
	try:
		session.execute("DROP USER %s" % username)
		print "User %s deleted successfully" % username
		return True
	except InvalidRequest as e:
		sys.exit("Error: " + str(e[0]))
	except Exception as e:
		sys.exit("Error: Exception executing DROP USER: " + str(e[0]))
#
# Ask a user for their password interactively
def getPasswdInput(username):
	while True:
		first_password = getpass.getpass(prompt="Please enter password for user " + username + ": ")
		second_password = getpass.getpass(prompt="Please enter matching password: ")

		if first_password == second_password:
			return first_password
		else:
			print "Error: Passwords do not match. Please try your luck again."
#
# Change a cassandra user's password
def passwdCassandraUser(session, username, password):
	# I should have paid attention to Mrs. Kuffner
	hashola = bcrypt.hashpw(password, bcrypt.gensalt(4))

	try:
		session.execute(
			"""
			INSERT INTO system_auth.credentials (username, salted_hash)
			VALUES (%s, %s)
			""",
			(username, hashola)
		)
		return True
	except Exception as e:
		sys.exit("Error: Exception executing password update for user " + username + ": " + str(e))

# Revoke a user's rights
def revokeCassandraUser(session, resource, username):
	try:
		session.execute("REVOKE ALL PERMISSIONS ON KEYSPACE \"%s\" FROM %s" % (resource, username))
		print "All permissions on %s have been REVOKED from user %s." % (resource, username)
		return True
	except Exception as e:
		sys.exit("Error: Exception while attempting to revoke permissions on %s from user %s: %s" % (resource, username, e))

# Helper function to try / except looking for CLI options
def tryValue(action, component, position):
	try:
		value = sys.argv[position]
	except IndexError as e:
		sys.exit("Error: Action %s reqtures a %s component." % (action, component))

	return value

# Grant a user rights
def grantCassandraUser(session, resource, username, grants):
	grants_length = len(grants)
	# We can assume if the grants requested is only one element and it contains ALL:
	if grants_length == 1 and grants[0] == "ALL":
		try:
			session.execute("GRANT ALL PERMISSIONS ON KEYSPACE \"%s\" TO %s" % (resource, username))
			print "Granting all privileges on %s to %s" % (resource, username)
			return True
		except Exception as e:
			sys.exit("Error: Exception while attempting to grant user %s permissions on %s: %s" % (username, resource, e))
	# If the grants array len is larger than one, we can assume we're specifying multiple grants
	elif grants_length >= 1:
		grants_message = "Granted "
		# One query per grant. yay. 
		for grant in range(grants_length):
			if grant == 0:
				grants_message = grants_message + grants[grant]
			else:
				grants_message = grants_message + ", " + grants[grant]

			try:
				session.execute("GRANT %s ON KEYSPACE \"%s\" TO %s" % (grants[grant], resource, username))
			except Exception as e:
				sys.exit("Error: Exception while attempting to grant user %s permissions on %s: %s" % (username, resource, e))

		print grants_message + " on %s to %s." % (resource, username)
		return True
	# This is actually caught when this function is called, but we should protect ourselves here too
	else:
		sys.exit("Error: Please supply some grants with your grant option.")

def main():
	# Parse command line arguments
	# actions (list, create, delete, passwd, grant, revoke)
	cumin_args = {}
	cumin_args['action'] = tryValue('any', 'action', 1)

	if cumin_args['action'] == 'help':
		sys.exit(displayHelp())
	cumin_args['hostname'] = tryValue(cumin_args['action'], 'hostname', 2)
	
	# Read our configuration file and set username / password
	config = ConfigParser.SafeConfigParser()
	if 'CUMIN_CONF' in os.environ.keys():
		config.read(os.environ['CUMIN_CONF'])
	else:
		config.read('/etc/cumin.conf')
	
	# Get our database credentials from the conf
	try:
		cassandra_username = config.get('cassandra', 'username')
		cassandra_password = config.get('cassandra', 'password')
	except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
		sys.exit("Error: Config file missing a required section or option: (" + e[0] + ")")
	except Exception as e:
		sys.exit("Error: Unknown exception reading config file: " + str(e[0]))

	# Determine which database we want and connect
	cassandra_database = True # Replace all this later
	if cassandra_database == True:
		try:
			session = connectCassandra(cumin_args['hostname'], cassandra_username, cassandra_password)
		except Exception as e:
			sys.exit("Error: Exception connecting to host: " + str(e[0]))

	# List users
	if cumin_args['action'] == 'list':
		listCassandraUsers(session)
	else:
		cumin_args['username'] = tryValue(cumin_args['action'], 'username', 3)
		# Create a user
		if cumin_args['action'] == 'create':
			# cumin create db01.svcs.xxx joeuser superuser
			if len(sys.argv) >= 5:
				cumin_args['superuser'] = sys.argv[4]
			else:
				cumin_args['superuser'] = "NOSUPERUSER"
			createCassandraUser(session, cumin_args['username'], cumin_args['superuser'])

		# Delete a user
		elif cumin_args['action'] == 'delete':
			deleteCassandraUser(session, cumin_args['username'])

		# Update user's password
		elif cumin_args['action'] == 'passwd':
			if passwdCassandraUser(session, cumin_args['username'], getPasswdInput(cumin_args['username'])):
				print "Set password for user %s successfully." % cumin_args['username']

		# Update user's grants
		elif cumin_args['action'] == 'grant':
			# Required - A Keyspace, Table, Resource of some kind. 
			cumin_args['resource'] = tryValue(cumin_args['action'], 'resource', 4)
			if len(sys.argv) >= 6:
				# Make an array of grants if we have less than 'ALL'
				grants = []
				if sys.argv[5] == 'all':
					grants = ['ALL']
				else:
					for i in range(5, len(sys.argv)):
						grants.append(sys.argv[i].upper())

				grantCassandraUser(session, cumin_args['resource'], cumin_args['username'], grants)
			else:
				sys.exit("Error: Please supply at least one permission to grant.")
		#
		# Revoke user's grants
		elif cumin_args['action'] == 'revoke':
			revokeCassandraUser(session, tryValue(cumin_args['action'], 'resource', 4), cumin_args['username'])
#
if __name__ == '__main__':
	main()