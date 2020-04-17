#!/usr/bin/env python3

class RSA():
    """
    Asymmetric key cryptography algorithm based ( public key cryptography and private key cryptography )
    RSA is a public-key cryptographic algorithm based on the difficulty of factoring large integers (prime numbers).
    The algorithm is typically used for both encryption and authentication (digital signature).
    """
    
    @staticmethod
    def gcd(a, b):
        """
        The greatest common divisor (gcd) of two or more integers,
        which are not all zero, is the largest positive integer that divides each of the integers.
        """
        while b:
            a, b = b, a % b
        return a
    
    @classmethod
    def generate_keys(self, prime_a, prime_b):
        """
        Key generation: Retur pair keys, The public key is ( n , e ) , i.e. the modulus and the cipher exponent. 
        The private key is ( n , d ) , i.e. the modulus and the decryption exponent, which must be kept secret.
        """
        # Choose two different prime numbers.
        self.prime_factor = prime_a * prime_b
        
        #  φ(Phi) is Euler's function to calculate: φ(n) = (p-1)*(q-1) ] based on the following two properties of Euler's function 
        #  [ φ(p) = p -1 if p is prime ] and [ If m and n are prime to each other, then φ ( m n ) = φ ( m ) φ ( n ) ].
        totient = (prime_a - 1) * (prime_b - 1)
        
        # determine d (by modular arithmetic) that satisfies the congruence e ⋅ d ≡ 1 ( mod φ ( n ) )
        # That is to say, that d is the inverse modular multiplier of e mod φ ( n ).
        public_keys = []
        for i in range(totient):
            if self.gcd(i, totient) == 1:
                public_keys.append(i)
        # select a positive integer smaller than φ ( n ) that is coprime with φ ( n ).
        self.public_key = public_keys[4]
        self.private_key = 0
        n = -1
        while n != 0:
            self.private_key += 1
            # Calculate n which is the product of p and q (selected prime numbers). n is used as the module for both public and private keys. 
            n = (self.public_key * self.private_key - 1) % totient
        return (self.prime_factor, self.public_key, self.private_key)

    @classmethod
    def encrypt(self, plaintext):
        """
        person A sends public key ( n , e ) to person B and keeps the private key secret. Now person A wants to send a (encrypted) message M to person B.
        First, Person A converts M into an integer smaller than n by means of a reversible protocol agreed beforehand and which must ensure that m and n are co-primes.
        """
        plaintext_chars = [ord(char) for char in plaintext]
        # Now to encrypt sol it is sufficient to calculate by the operation c ≡ m e ( mod n ) 
        message_encrypted = ''.join([chr(char**self.public_key % self.prime_factor) for char in plaintext_chars])
        return message_encrypted

    @classmethod
    def decrypt(self, message_encrypted):
        """
        Person B can recover m from c using its private key exponent d by the following calculation: m ≡ c d ( mod n )  
        """
        message_encrypted_chars = [ord(char) for char in message_encrypted]
        message = ''.join([chr(char**self.private_key % self.prime_factor) for char in message_encrypted_chars])
        return message

def main():
    # init RSA algorithm
    rsa = RSA()
    # select 2 random prime numbers (depending on their length varies your security)
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

if __name__=="__main__":
    main()
