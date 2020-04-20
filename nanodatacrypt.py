#!/usr/bin/env python3

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
    
    @staticmethod
    def title(self):
        pass
    
    def get_message(self):
        with open(self._filename,'r') as file:
            plaintext = file.read().replace('\n', '')
        file.close()
        return plaintext
    
    def get_encrypted_message(self):
        with open(self._encrypted_file,'r') as file:
            message_encryted = file.read().replace('\n', '')
        file.close()
        return message_encryted
    
    def assert_plaintext(self,plaintext,encrypted,decrypted):
        if plaintext == decrypted:
            print('Thats Great,Decrypted successfull!')
            print(f'Original Message: {plaintext}\nEncrypted Message: {encrypted}'
            f'\nDecrypted Message: {decrypted}')
        else:
            print('Ups!, Someting wrong :C')
    
    def file_encrypt(self,message_encryted):
        file = open(self._encrypted_file,'w')
        file.write(str(message_encryted))
        file.close()
    
    @staticmethod
    def usage():
        print ('\t  Usage: nanodatacrypt [options] | <misc>' )
        print ('\t  -a <aes>: simetric algorithm  [ AES ]')
        print ('\t  -r <rsa>: asymetric algorithm [ RSA ]')
        print ('\t  -h <help>')
    
def main(argv):
    try:
        opts, args = getopt.getopt(argv,'har',['help','aes','rsa'])
        datacrypt = NanoDataCrypt(args[0])
        plaintext = datacrypt.get_message()
    except getopt.GetoptError:
        NanoDataCrypt.usage()
        sys.exit(2)
    for opt , arg in opts:
        print(opt,args[0])
        if opt in ('-h', '--help'):
            NanoDataCrypt.usage()
        elif opt in ('-a', '--aes'):
            secret_key   = 'somepass'.encode('utf-8')
            plaintext    = plaintext.encode('utf-8')
            secret_key = int( secret_key.hex(), 16 ) 
            message_int  = int( plaintext.hex(), 16 ) 
            aes = AES(secret_key)
            encrypted = aes.encrypt(message_int)
            datacrypt.file_encrypt(encrypted)
            #decrypted = aes.decrypt(encrypted)
            #decrypted = bytes.fromhex((hex(decrypted)[2:]))
            #datacrypt.assert_plaintext(plaintext,encrypted,decrypted)
        elif opt in ('-r', '--rsa'):
            rsa = RSA()
            keys = rsa.generate_keys(307, 311)
            print(keys)
            encrypted = rsa.encrypt(plaintext)
            datacrypt.file_encrypt(encrypted)
            decrypted = rsa.decrypt(encrypted)
            datacrypt.assert_plaintext(plaintext,encrypted,decrypted)
        else:
            assert False, "unhandled option"
    sys.exit()
            
if __name__ == '__main__':
    main(sys.argv[1:])
