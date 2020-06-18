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
            secret_key   = input('Enter your secret phrase:')
            secret_key   = secret_key.encode('utf-8')
            secret_key = int( secret_key.hex(), 16 ) 
            aes = AES(secret_key)
            if args[1] == '-e' or args[0] == '--encrypt':
                plaintext = (datacrypt.get_message()).encode('utf-8')
                message_int  = int( plaintext.hex(), 16 )
                encrypted = aes.encrypt(message_int,128)
                datacrypt.file_encrypt(encrypted)
                os.remove(datacrypt.get_filename())
            elif args[1] == '-d' or args[0] == '--decrypt':
                encrypted = int(datacrypt.get_encrypted_message())
                decrypted = aes.decrypt(encrypted,128)
                datacrypt.file_decrypt(decrypted)
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
