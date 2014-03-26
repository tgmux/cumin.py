cumin.py
========

A User Manager Utility for Cassandra 1.2.x

## Installation

    $ for foo in $(cat requirements.txt); do sudo pip install $foo; done

## Usage
```
Usage: cumin.py [options]

Options:
  -h, --help            show this help message and exit
  --conf=CONFIG_PATH    Path to config file (/etc/cumin.conf default)
  -H DATABASE_HOSTNAME, --host=DATABASE_HOSTNAME
                        Database Hostname
  -u DATABASE_USERNAME, --user=DATABASE_USERNAME
                        Username to manipulate
  -w DATABASE_PASSWORD, --pw=DATABASE_PASSWORD
                        Password to set
  -r DATABASE_RESOURCE, --resource=DATABASE_RESOURCE
                        Resource to grant
  -l, --list            List cassandra users
  -n, --new             Create a new user
  -d, --delete          Delete an existing user
  -p, --passwd          Change a user's password
  -g, --grant           Modify user's grants
  --alter               Alter permission
  --create              Create permission
  --authorize           Authorize permission
  --drop                Drop permission
  --modify              Modify permission
  --select              Select permission
  --all                 Grant all permissions
  --revoke              Revoke all permissions
  --super               Create a superuser
```

### Examples
* Read only access 
`$ cumin.py -H mycassandrahost -g -u auser -r akeyspace --select`

* Create a new superuser 
`$ cumin.py -H anothercassandrahost -n -u bossman --super`

* Change a user's password
`$ cumin.py -H thatcassandrahost -p -u buser`
`$ cumin.py -H thatcassandrahost -p -u buser -w secretpassword`
