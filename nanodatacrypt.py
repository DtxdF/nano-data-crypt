#!/usr/bin/env python3

import os
import sys
import getopt
import getpass

from algorithms.RSA import RSA
from algorithms.AES import AES

class NanoDataCrypt:
    
    def __init__(self,filename):
        self.filename = filename
        self.outfile = filename + '.cpt'
        
    def __repr__(self):
        return 'NanoDataCrypt({})'.format(self.filename)
    
    def title(self):
        pass
    
    def get_message(self):
        with open(self.filename,'r') as file:
            data = file.read().replace('\n', '')
        file.close()
        return data
    
    def file_encrypt(self,message):
        with open(self.outfile, 'a'):
            os.utime(self.outfile, None)
    
    def file_decrypt(self):
        pass
    
    def rsa(self):
        rsa = RSA()
        keys = rsa.generate_keys(307, 311)
        print(keys)
        message = 'Hello World!'
        encrypted_message = rsa.encrypt(message)
        decrypted_message = rsa.decrypt(encrypted_message)
        if message == decrypted_message:
            print('Thats Great,Decrypted successfull!')
            print(f'Original Message: {message}\nEncrypted Message: {encrypted_message}'
            f'\nDecrypted Message: {decrypted_message}')
        else:
            print('Ups!, Someting wrong :C')
            
    def aes(self):
        secret_key   = 'somepass'.encode('utf-8')
        message    = 'Hello World!'.encode('utf-8')
        secret_key = int( secret_key.hex(), 16 ) 
        plaintext  = int( message.hex(), 16 ) 
        aes = AES(secret_key)
        encrypted = aes.encrypt(plaintext)
        decrypted = aes.decrypt(encrypted)
        decrypted = bytes.fromhex((hex(decrypted)[2:]))
        if message == decrypted:
            print('Thats Great,Decrypted successfull!')
            print(f'Original Message: {message}\nEncrypted Message: {encrypted}'
                f'\nDecrypted Message: {decrypted}')
    
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
        message = datacrypt.get_message()
        datacrypt.file_encrypt(message)
    except getopt.GetoptError:
        NanoDataCrypt.usage()
        sys.exit(2)
    for opt , arg in opts:
        print(opt,args[0])
        if opt in ('-h', '--help'):
            NanoDataCrypt.usage()
        elif opt in ('-a', '--aes'):
            datacrypt.aes()
        elif opt in ('-r', '--rsa'):
            datacrypt.rsa()
        else:
            assert False, "unhandled option"
    sys.exit()
            
if __name__ == '__main__':
    main(sys.argv[1:])
