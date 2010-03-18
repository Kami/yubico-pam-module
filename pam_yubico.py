# -*- coding: utf-8 -*-
#
# Name: Yubico PAM module
# Description: Python PAM module which allows you to integrate the Yubikey into your
# existing user authentication infrastructure.
#
# This module is based on the original PAM module written in C so it currently uses the
# same configuration options, but the current version does not support LDAP.
#
# For more information about the configuration options, visit the original C module
# website at http://code.google.com/p/yubico-pam/wiki/ReadMe
#            
# Author: Tomaž Muraus (http://www.tomaz-muraus.info)
# Version: 1.1.0

# Requirements:
# - Python >= 2.6
# - pam
# - python-pam
# - pam-python (http://ace-host.stuart.id.au/russell/files/pam_python/)

import os
import logging
import urllib

# Constants
API_URL = 'https://api.yubico.com/wsapi/verify?id=%s&otp=%s'
CLIENT_ID_LENGTH = 12
TOKEN_LENGTH = 44
KEYS_MAPPING_DIRECTORY_NAME = '.yubico'
KEYS_MAPPING_FILE_NAME = 'authorized_yubikeys'

# Setup logging
logging.basicConfig(filename = '/var/log/pam_yubico.log', filemode = 'a', level = logging.DEBUG, format = '%(asctime)s %(levelname)-8s %(message)s', datefmt = '%d.%m.%Y %H:%M:%S')

class MessagePrompt():
    # Dummy Message class
    msg = ''
    msg_style = 0

def pam_sm_authenticate(pamh, flags, argv):
    user = pamh.user
    arguments = _parse_arguments(argv)
    user_mappings = _parse_mapping_files(arguments['authfile'])
    
    if not user in user_mappings:
        # No client id is set for this username
        logging.debug('No client ID is set for user %s' % (user))
        return pamh.PAM_AUTHINFO_UNAVAIL

    prompt = MessagePrompt()
    prompt.msg = 'Yubikey for `%s`: ' % (user)
    prompt.msg_style = pamh.PAM_PROMPT_ECHO_OFF
    
    response = pamh.conversation(prompt).resp
    otp = response
    client_id = otp[:12]
    
    logging.debug('OTP = %s' % (otp))
    logging.debug('client ID = %s' % (client_id))
    if arguments['alwaysok'] == 1:
        # Presentation mode is enabled
        logging.debug('Presenation mode is ON')
        return pamh.PAM_SUCCESS
    
    if user_mappings[user] != client_id:
        # Client ID is not matching
        logging.debug('Client ID in the file does not match the one provided by the OTP')
        return pamh.PAM_AUTH_ERR

    if not otp:
        # No OTP is provided by the user
        logging.debug('No OTP provided')
        return pamh.PAM_AUTH_ERR
    
    if len(otp) != TOKEN_LENGTH:
        # Invalid OTP length
        logging.debug('Invalid OTP length')
        return pamh.PAM_AUTH_ERR

    valid_otp = _check_otp(arguments['url'], arguments['id'], otp)
    
    if not valid_otp:
        logging.debug('Error, the provided OTP is invalid')
        return pamh.PAM_AUTH_ERR
    
    # Everything went well and the provided OTP is valid    
    logging.debug('Sucess, the provided OTP is OK')
    return pamh.PAM_SUCCESS

def pam_sm_setcred(pamh, flags, argv):
    # @todo: not implemented
    return pamh.PAM_CRED_UNAVAIL

def pam_sm_acct_mgmt(pamh, flags, argv):
    # @todo: not implemented
    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    # @todo: not implemented
    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    # @todo: not implemented
    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    # @todo: not implemented
    return pamh.PAM_SUCCESS

def _parse_mapping_files(auth_file = None):
    """ Parses the mapping files and returns a dictionary of username=client_id pairs. """
    
    mappings = {}
    mapping_files = []
    # We read the global mapping file if it's set
    if auth_file and os.path.exists(auth_file):
        logging.debug('Global mapping file found: %s' % (auth_file))
        mapping_files.append(auth_file)
        
    # And then the user own mapping file (if it exists)
    user_key_file = os.path.join(os.path.expanduser('~'), KEYS_MAPPING_DIRECTORY_NAME + '/') + KEYS_MAPPING_FILE_NAME
    if os.path.exists(user_key_file):
        logging.debug('User mapping file found: %s' % (user_key_file))
        mapping_files.append(user_key_file)
    
    for mapping_file in mapping_files:
        with open(mapping_file, 'r') as file:
            line = file.readline()
            
            while line:
                try:
                    line = line.strip()
                    line_split = line.split(':')
                    username = line_split[0]
                    client_id = line_split[1]
                    
                    if len(client_id) != CLIENT_ID_LENGTH:
                        # Invalid cliend ID length
                        continue
                    
                    mappings[username] = client_id
                except KeyError:
                    continue
                finally:
                    line = file.readline()
    
    return mappings            

def _parse_arguments(args = None):
    """ Parses the provided arguments. """
    
    arguments = {
            'id': -1,
            'debug': False,
            'alwaysok': 0,
            'authfile': None,
            'url': API_URL
    }
    
    if args:
        if 'debug' in args:
            arguments['debug'] = True
        else:
            logging.disable(logging.FATAL)
        
        logging.debug('Arguments')
        for argument in args:
            if len(argument.split('=')) != 2:
                continue
            
            (key, value) = argument.split('=')
            if key in arguments:
                if key in ['id', 'alwaysok']:
                    value = int(value)
                
                logging.debug('%s = %s' % (key, value)) 
                arguments[key] = value
            
    return arguments

def _check_otp(api_url, client_id, otp):
    """ Returns True is the OTP is valid, False otherwise. """
    
    response = urllib.urlopen(api_url % (client_id, otp)).read()
    
    try:
        status = response.split('status=')[1].strip()
        logging.debug('Yubico server returned: status=%s' % (status))
    except KeyError:
        logging.debug('Yubico server returned no or an invalid response (missing status)')
        return False
    
    if status == 'OK':
        return True
    
    return False