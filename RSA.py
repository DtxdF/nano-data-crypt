#!/usr/bin/env python3

class RSA():
    
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @classmethod
    def generate_keys(self, prime_a, prime_b):
        self.prime_factor = prime_a * prime_b
        totient = (prime_a - 1) * (prime_b - 1)
        public_keys = []
        for i in range(totient):
            if self.gcd(i, totient) == 1:
                public_keys.append(i)
        self.public_key = public_keys[4]
        self.private_key = 0
        n = -1
        while n != 0:
            self.private_key += 1
            n = (self.public_key * self.private_key - 1) % totient
        return (self.prime_factor, self.public_key, self.private_key)

    @classmethod
    def encrypt(self, plaintext):
        plaintext_chars = [ord(char) for char in plaintext]
        message_encrypted = ''.join([chr(char**self.public_key % self.prime_factor) for char in plaintext_chars])
        return message_encrypted

    @classmethod
    def decrypt(self, message_encrypted):
        message_encrypted_chars = [ord(char) for char in message_encrypted]
        message = ''.join([chr(char**self.private_key % self.prime_factor) for char in message_encrypted_chars])
        return message

def main():
    rsa = RSA()
    print(rsa.generate_keys(307, 311))
    message = 'Hello World!'
    encrypted_message = rsa.encrypt(message)
    decrypted_message = rsa.decrypt(encrypted_message)
    if message == decrypted_message:
        print('Thats Great,Decrypted successfull!')
        print(f'message: {message}\nencrypted message: {encrypted_message}'
              f'\ndecrypted message: {decrypted_message}')
    else:
        print('Ough, someting wrong here  ... !')

if __name__=="__main__":
    main()
