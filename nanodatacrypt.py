#!/usr/bin/env python3

import os

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
    
def main():
    datacrypt = NanoDataCrypt('hi.txt')
    message = datacrypt.get_message()
    datacrypt.file_encrypt(message)
    
if __name__=="__main__":
    main()
