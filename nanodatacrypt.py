#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import getopt
import getpass

from algorithms.RSA import RSA
from algorithms.AES import AES

class NanoDataCrypt:
    
    def __init__(self,filename):
        self._filename = filename
        self._encrypted_file = filename + '.cpt'
        
    def __repr__(self):
        return 'NanoDataCrypt({})'.format(self._filename)
        
    def get_filename(self): 
        return self._filename
    
    def get_encrypted_file(self): 
        return self._encrypted_file
    
    def get_message(self):
        with open(self._filename,'r') as file:
            plaintext = file.read().replace('\n', '')
        file.close()
        return plaintext
    
    def get_plaintext_lines(self):
        plaintext_lines = []
        with open(self._filename,'r') as file:
            line = file.readlines()
            plaintext_lines.append(line)
        file.close()
        return plaintext_lines
    
    def get_encrypted_message(self):
        with open(self._encrypted_file,'r') as file:
            message_encryted = file.read()
        file.close()
        return message_encryted
    
    def get_encrypted_lines(self):
        encrypted_lines = []
        with open(self._encrypted_file,'r') as file:
            line = file.readlines()
            if line == '':
                line = b''
            encrypted_lines.append(line)
        file.close()
        return encrypted_lines
    
    def assert_plaintext(self,plaintext,decrypted):
        if plaintext == decrypted:
            print('Thats Great,Decrypted successfull!')
            print(f'Original Message: {plaintext} \n Decrypted Message: {decrypted}')
        else:
            print('Ups!, Someting wrong :C')
    
    def file_encrypt(self,message_encryted):
        file = open(self._encrypted_file,'w')
        file.write(str(message_encryted))
        file.close()
    
    def file_decrypt(self,message_decryted):
        file = open(self._filename,'w')
        file.write(str(message_decryted))
        file.close()
    
    def get_secret_key(self):
        secret_key = getpass.getpass()
        secret_key = secret_key.encode('utf-8')
        secret_key = int( secret_key.hex(), 16 )
        return secret_key
    
    @staticmethod
    def usage():
        print ('\t  Usage: nanodatacrypt [option] <file> [args]' )
        print ('\t  -e <encrypt> [args]')
        print ('\t  -d <decrypt> [args]')
        print ('\t  -a <aes>: simetric algorithm  [ AES ]')
        print ('\t  -r <rsa>: asymetric algorithm [ RSA ]')
        print ('\t  -h <help>')
    
def main(argv):
    try:
        opts, args = getopt.getopt(argv,'har',['help','aes','rsa'])
        datacrypt = NanoDataCrypt(args[0])
    except getopt.GetoptError:
        NanoDataCrypt.usage()
        sys.exit(2)
    for opt , arg in opts:
        if opt in ('-h', '--help'):
            NanoDataCrypt.usage()
        elif opt in ('-a', '--aes'):
            secret_key = datacrypt.get_secret_key()
            aes = AES(secret_key)
            if args[1] == '-e' or args[0] == '--encrypt':
                plaintext_lines = datacrypt.get_plaintext_lines()
                file = open(args[0]+'.cpt','w')
                for plaintext in plaintext_lines[0]:
                    plaintext = (plaintext.replace('\n', '')).encode('utf-8')
                    if plaintext != b'':
                        message_int = int( plaintext.hex(), 16 )
                        encrypted = aes.encrypt(message_int,128)
                        file.write(str(encrypted)+'\n')
                    else:
                        file.write('\n')
                file.close()
                os.remove(datacrypt.get_filename())
            elif args[1] == '-d' or args[0] == '--decrypt':
                encrypted_lines = datacrypt.get_encrypted_lines()
                file = open(args[0],'w')
                for cyphertext in encrypted_lines[0]:
                    if cyphertext != '\n':
                         plaintext = aes.decrypt( int( cyphertext, 10 ) ,128)
                         plaintext = bytes.fromhex((hex(plaintext)[2:]))
                         print(plaintext)
                         file.write(str(plaintext)+'\n')
                    else:
                        print('empty line!')
                        file.write('\n')
                file.close()
                os.remove(datacrypt.get_encrypted_file())
        
        elif opt in ('-r', '--rsa'):
            rsa = RSA()
            keys = rsa.generate_keys(307, 311)
            print(keys)
            if args[1] == '-e' or args[0] == '--encrypt':
                plaintext = datacrypt.get_message()
                encrypted = rsa.encrypt(plaintext)
                datacrypt.file_encrypt(encrypted)
                os.remove(datacrypt.get_filename())
            elif args[1] == '-d' or args[0] == '--decrypt':
                encrypted = datacrypt.get_encrypted_message()
                decrypted = rsa.decrypt(encrypted)
                datacrypt.file_decrypt(decrypted)
                os.remove(datacrypt.get_encrypted_file())
        else:
            assert False, "unhandled option"
    sys.exit()
            
if __name__ == '__main__':
    main(sys.argv[1:])
