#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import os
import yaml
from passlib.hash import sha512_crypt
from Crypto.PublicKey import RSA

def main(argv):
    """Main function
    """

    parser = argparse.ArgumentParser(description='Configure users')
    parser.add_argument('--credential-path', type=str, default=None,
                        help='Path to credentials directory with users_cfg.yml')
    args = parser.parse_args()

    smb_path = os.path.join(args.credential_path, 'configs', 'smb_cfg.yml')
    crypt_path = os.path.join(args.credential_path, 'configs', 'users_cfg_crypt.yml')
    clear_path = os.path.join(args.credential_path, 'configs', 'users_cfg.yml')
    empty_path = os.path.join(args.credential_path, 'configs', 'users_cfg_empty.yml')
    private_key_path = os.path.join(args.credential_path, 'user_private_keys')
    public_key_path = os.path.join(args.credential_path, 'user_public_keys')

    with open(clear_path, 'r') as uc, \
         open(empty_path, 'w') as ep, \
         open(crypt_path, 'w') as out_conf, \
         open(smb_path, 'w') as smb_conf:
        doc = yaml.load(uc)

        users = doc['users']
        crypt_users = list()
        empty_users = list()
        for user in users:
            username = user['username']
            password = user['clear-password']
            crypt_pass = sha512_crypt.encrypt(password)
            print('Adding user: {}'.format(username))

            new_user = user.copy()
            del new_user['clear-password']
            new_user['crypt-pass'] = crypt_pass
            crypt_users.append(new_user)

            # Note - this file gets used by useradd, password gets placed as-is in /etc/passwd
            # Set password here to any short string - not possible to login since sha512 hash
            # returns long string, sha512(any_string) != short string
            new_user = user.copy()
            del new_user['clear-password']
            new_user['crypt-pass'] = 'xxxxxxxx'
            empty_users.append(new_user)

        out_dict = {'users': crypt_users}
        out_dat = yaml.dump(out_dict)
        out_conf.write(out_dat)

        out_dict = {'users': empty_users}
        out_dat = yaml.dump(out_dict)
        ep.write(out_dat)

        samba_users = list()
        for user in users:
            username = user['username']
            password = user['clear-password']
            for char in '!();<>&':
                password = password.replace(char, r'\{}'.format(char))
            # password = password.replace('!', r'\!')
            # password = password.replace('(', r'\(')
            # password = password.replace(')', r'\)')
            new_user = {'name': username, 'password': password}
            samba_users.append(new_user)

        out_dict = {'samba_users': samba_users}
        out_dat = yaml.dump(out_dict)
        smb_conf.write(out_dat)

    for user in crypt_users:
        username = user['username']
        private_key_file_path = os.path.join(private_key_path, username) + '_key'
        public_key_file_path = os.path.join(public_key_path, username) + '_key.pub'

        if not os.path.isfile(private_key_file_path):
            print('Generating new key for user {}'.format(username))
            key = RSA.generate(2048)
            with open(private_key_file_path, 'w') as content_file:
                content_file.write(key.exportKey('PEM'))
            pubkey = key.publickey()
            with open(public_key_file_path, 'w') as content_file:
                content_file.write(pubkey.exportKey('OpenSSH'))

    return 0


if __name__ == "__main__":
   sys.exit(main(sys.argv[1:]))