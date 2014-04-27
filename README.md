cumin.py
========

A User Manager Utility for Cassandra 1.2.x for python 2.7

## Installation

    $ for foo in $(cat requirements.txt); do sudo pip install $foo; done

## Usage
```
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
```

### Examples
Read only access:

`$ cumin.py grant mycassandrahost auser akeyspace select`

Create a new superuser:

`$ cumin.py create mycassandrahost bossman superuser`

Create a regular user:

`$ cumin.py create mycassandrahost normaluser`

Change a user's password:

`$ cumin.py passwd mycassandrahost normaluser`