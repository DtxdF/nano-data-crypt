#!/usr/bin/env python3

class AES:
    """
    AES Is Symmetric key cryptography algorithm ( secret key cryptograph ) AES ( Advanced Encryption Standard )
    The Advanced Encryption Standard (AES), also known by its original name Rijndael
    """
    
    # rcon Round Constant (Key schedule)
    # AES uses up to rcon 10 for AES-128, up to rcon 8 for AES-192, and up to rcon 7 for AES-256. The key schedule.
    
    rcon_a = ( 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a )
    
    rcon_b = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # S-Box ( substitution-box ) It serves to obscure the relationship between the key and the ciphertext, a property of Shannon's confusion.
    # S-box takes m number of input bits, m, and transforms them into n number of output bits, n, where n is not necessarily equal to m. 
    # An m×n S-box can be implemented as a lookup table with 2m of n-bit words each. 
    sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    # Inverse S -Box The Rijndael S-box is a substitution box (lookup table) used in the Rijndael cipher
    inversesbox = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )
    
    ntime       = lambda self, n: (((n << 1) ^ 0x1B) & 0xFF) if (n & 0x80) else (n << 1)
    
    # In the MixColumns step, the four bytes of each column of the state are combined using an invertible linear transformation. 
    # The MixColumns function takes four bytes as input and outputs four bytes, where each input byte affects all four output bytes. 
    # Together with ShiftRows, MixColumns provides diffusion in the cipher. 
    mix_columns = lambda self, s : [ self.mix_single_column(s[i]) for i in range(4) ]
    
    def __init__(self, secret_key):
        self.key_expansion(secret_key)
    
    def plaintext_to_matrix(self,plaintext):
        """
        Pass a message in plaintext to simple bytes matrix
        """
        matrix = []
        for i in range(16):
            byte = (plaintext >> (8 * (15 - i))) & 0xFF
            if i % 4 == 0:
                matrix.append([byte])
            else:
                matrix[ (int)(i / 4) ].append(byte)
        return matrix

    def matrix_to_plaintext(self,matrix):
        """
        passsimple bytes matrix to message in plaintext
        """
        plaintext = 0
        for i in range(4):
            for j in range(4):
                plaintext |= ( matrix[i][j] << (120 - 8 * (4 * i + j)) )
        return plaintext

    def key_expansion(self, secret_key):
        """
        KeyExpansion : round keys are derived from the cipher key using Rijndael's key schedule.
        AES requires a separate 128-bit round key block for each round plus one more.
        """
        self.round_keys = self.plaintext_to_matrix(secret_key)
        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0]        \
                     ^ self.sbox[self.round_keys[i - 1][1]]  \
                     ^ self.rcon_b[(int)(i / 4)]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)
    
    def add_round_key(self, s, k):
        """
        In the AddRoundKey step, the subkey is combined with the state. For each round, a subkey is derived from the main key using Rijndael's
        key schedule; each subkey is the same size as the state. The subkey is added by combining each byte of the state with the corresponding 
        byte of the subkey using bitwise XOR. 
        """
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]
    
    def sub_bytes(self, s):
        """
        In the SubBytes step, each byte a[i,j] in the state array is replaced with a SubByte S( a[i,j]) using an 8-bit substitution box. 
        This operation provides the non-linearity in the cipher. The S-box used is derived from the multiplicative inverse over GF(2^8),
        known to have good non-linearity properties.
        """
        for i in range(4):
            for j in range(4):
                s[i][j] = self.sbox[s[i][j]]

    def rev_sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = self.inversesbox[s[i][j]]

    def shift_rows(self, s):
        """
        The ShiftRows step operates on the rows of the state; it cyclically shifts the bytes in each row by a certain offset. 
        For AES, the first row is left unchanged. Each byte of the second row is shifted one to the left. 
        Similarly, the third and fourth rows are shifted by offsets of two and three respectively
        """
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

    def rev_shift_rows(self, s):
        """
        Reverse process of the previous method, reverses the change of rows
        """
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

    def mix_single_column(self, a):
        """
        Mix only a column in particular
        """
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ self.ntime(a[0] ^ a[1])
        a[1] ^= t ^ self.ntime(a[1] ^ a[2])
        a[2] ^= t ^ self.ntime(a[2] ^ a[3])
        a[3] ^= t ^ self.ntime(a[3] ^ u)
    
    def rev_mix_columns(self, s):
        """
        Reverse process of the previus method, reverses the mix column in particular
        """
        for i in range(4):
            u = self.ntime(self.ntime(s[i][0] ^ s[i][2]))
            v = self.ntime(self.ntime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v
        self.mix_columns(s)
    
    def round_encrypt(self, state_matrix, key_matrix):
        """
        Based state matrix and key matrix ,init process cycle round encrypt : subBytes, ShiftRows, MixColumns, AddRoundKey 
        """
        self.sub_bytes(state_matrix)
        self.shift_rows(state_matrix)
        self.mix_columns(state_matrix)
        self.add_round_key(state_matrix, key_matrix)

    def round_decrypt(self, state_matrix, key_matrix):
        """
        Based state matrix and key matrix ,init process cycle round decrypt : AddRoundKey, revMixColumns, revShiftRows, revsubBytes  
        """
        self.add_round_key(state_matrix, key_matrix)
        self.rev_mix_columns(state_matrix)
        self.rev_shift_rows(state_matrix)
        self.rev_sub_bytes(state_matrix)
    
    def encrypt(self, plaintext):
        """
        Encrypt message plaintext
        """
        self.plain_state = self.plaintext_to_matrix(plaintext)
        self.add_round_key(self.plain_state, self.round_keys[:4])

        for i in range(1, 10):
            self.round_encrypt(self.plain_state, self.round_keys[4 * i : 4 * (i + 1)])
            
        self.sub_bytes(self.plain_state)
        self.shift_rows(self.plain_state)
        self.add_round_key(self.plain_state, self.round_keys[40:])

        return self.matrix_to_plaintext(self.plain_state)

    def decrypt(self, ciphertext):
        """
        Decrypt message cypher 
        """
        self.cipher_state = self.plaintext_to_matrix(ciphertext)
        self.add_round_key(self.cipher_state, self.round_keys[40:])
        self.rev_shift_rows(self.cipher_state)
        self.rev_sub_bytes(self.cipher_state)

        for i in range(9, 0, -1):
            self.round_decrypt(self.cipher_state, self.round_keys[4 * i : 4 * (i + 1)])
            
        self.add_round_key(self.cipher_state, self.round_keys[:4])

        return self.matrix_to_plaintext(self.cipher_state)

def main():
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

if __name__ == "__main__":
    main()
