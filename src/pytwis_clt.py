#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import parse
import pytwis

def pytwis_command_parser(raw_command):
    # Separate the command from its arguments.
    splited_raw_command = raw_command.split(' ', 1)
    command_with_args = [splited_raw_command[0]]

    # Some command (e.g., logout) may not have arguments.
    arg_dict = {}
    
    if command_with_args[0] == 'register':
        # register must have two arguments: username and password.
        if len(splited_raw_command) < 2:
            raise ValueError('register has NO arguments')
            
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('register has incorrect arguments')
        
        print('register: username = {}, password = {}'.format(arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == 'login':
        # login must have two arguments: username and password.
        if len(splited_raw_command) < 2:
            raise ValueError('login has NO arguments')
            
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('login has incorrect arguments')
        
        print('login: username = {}, password = {}'.format(arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == 'logout':
        pass
    elif command_with_args[0] == 'changepassword':
        pass
    elif command_with_args[0] == 'post':
        pass
    elif command_with_args[0] == 'follow':
        pass
    elif command_with_args[0] == 'followers':
        pass
    elif command_with_args[0] == 'timeline':
        pass
    elif command_with_args[0] == 'exit' or command_with_args[0] == 'quit':
        pass
    else:
        raise ValueError('Invalid pytwis command')
    
    command_with_args.append(arg_dict)
    
    return command_with_args

def pytwis_command_processor(twis, auth_secret, command_with_args):
    command = command_with_args[0]
    args = command_with_args[1]
    
    if command == 'register':
        succeeded, result = twis.register(args['username'], args['password'])
        if succeeded:
            print('Succeeded in registering {}'.format(args['username']))
        else:
            print('Failed to register {} with error = {}'.format(args['username'], result['error']))
    elif command == 'login':
        succeeded, result = twis.login(args['username'], args['password'])
        if succeeded:
            auth_secret.append(result['auth'])
            print('Succeeded in logging into username {}'.format(args['username']))
        else:
            print("Couldn't log into username {} with error = {}".format(args['username'], result['error']))
    elif command == 'logout':
        if len(auth_secret) == 0:
            # Not logged in
            print('Not logged in.')
            return
        
        succeeded, result = twis.logout(auth_secret[0])
        if succeeded:
            auth_secret[:] = []
            print('Logged out of username {}'.format(result['username']))
        else:
            print("Couldn't log out with error = {}".format(result['error']))
    else:
        pass

def pytwis_cli():
    # TODO: Add epilog for the help information about online commands after connecting to the Twitter clone.
    parser = argparse.ArgumentParser(description=\
                                     '''Connect to the Redis database of a Twitter clone and 
                                        then run commands to access and update the database.''')
    parser.add_argument('-d', '--hostname', dest='redis_hostname', default = '127.0.0.1', 
                        help='the Redis server hostname. If not specified, will be defaulted to 127.0.0.1.')
    parser.add_argument('-t', '--port', dest='redis_port', default = 6379,
                        help='the Redis server port. If not specified, will be defaulted to 6379.')
    parser.add_argument('-p', '--password', dest='redis_password', default = '',
                        help='the Redis server password. If not specified, will be defaulted to an empty string.')
    
    args = parser.parse_args()
    
    print('The input Redis server hostname is {}.'.format(args.redis_hostname))
    print('The input Redis server port is {}.'.format(args.redis_port))
    if args.redis_password != '':
        print('The input Redis server password is "{}".'.format(args.redis_password))
    else:
        print('The input Redis server password is empty.')
    
    try:
        twis = pytwis.Pytwis(args.redis_hostname, args.redis_port, args.redis_password)
    except ValueError as e:
        print('Failed to connect to the Redis server: {}'.format(str(e)),
              file=sys.stderr)
        return -1
    
    auth_secret = []
    while True:
        try:
            command_with_args = pytwis_command_parser(
                input("Please enter a command (register, login, logout, changepassword, post, follow, followers, timeline):\n{}:{}> "\
                      .format(args.redis_hostname, args.redis_port)))
            if command_with_args[0] == "exit" or command_with_args[0] == 'quit':
                # Log out of the current user before exiting.
                if len(auth_secret) > 0:
                    pytwis_command_processor(twis, auth_secret, ['logout', {}])
                print('pytwis is exiting.')
                return 0;
            
        except ValueError as e:
            print('Invalid pytwis command: {}'.format(str(e)),
              file=sys.stderr)
            continue
        
        pytwis_command_processor(twis, auth_secret, command_with_args)

if __name__ == "__main__":
    pytwis_cli()