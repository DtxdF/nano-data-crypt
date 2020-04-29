[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub release](https://img.shields.io/badge/release-v1.0.0-green)](https://github.com/d4rk6h05t/nano-data-crypt)

# nano-data-crypt
Nano data encrypt and decrypt is small application of  implementation of the functioning of a  system cryptography ( symmetric and  asymmetric key cryptography ) . Application written in Python3.8 to  encrypt data on a small scale, school project for the subject of cibersecurity. 
# Algorithms
  - __AES__
    AES Is Symmetric key cryptography algorithm ( secret key cryptograph ) AES ( Advanced Encryption Standard )
    The Advanced Encryption Standard (AES), also known by its original name Rijndael
  - __RSA__
    Asymmetric key cryptography algorithm based ( public key cryptography and private key cryptography )
    RSA is a public-key cryptographic algorithm based on the difficulty of factoring large integers (prime numbers).
    The algorithm is typically used for both encryption and authentication (digital signature).
    
    The basic principle on which the RSA algorithm is based is the search to find three very large positive integers e,
    d and n, so that with a modular exponent for all integers m { 0 ≤ m < n }: 
    
    ![equation](http://www.sciweavers.org/tex2img.php?eq=m%2Bsin%28mc%5E2%29&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)
    \begin{equation}
        $$(\mathrm{m}^\mathrm{e})^\mathrm{d}	\equiv \mathrm{m} ( \bmod \mathrm{n} )$$
     \end{equation}
# Usage nano data crypt
  Usage: nanodatacrypt [option]  <file> [argument] <br>
         -e --encrypt  <br>
         -d --encrypt  <br>
         -a <aes>: simetric algorithm  [ AES ]  <br>
         -r <rsa>: asymetric algorithm [ RSA ]  <br>
         -h <help>  
# Example
    ./nanodatacrypt.py -a myfile.txt -e
    ./nanodatacrypt.py -a myfile.txt -d
    python nanodatacrypt.py --aes myfile.txt --encrypt 
    python nanodatacrypt.py --aes myfile.txt --decrypt
    
    
# Requirements
The project can be used with __python3.8__for to build. However, it requires __python3.*__ as minimum.

# Installation of Package python
```sh
# normally this package is already installed in most unix-based 
# distributions e.g. GNU/Linux, Freebsd, etc.
# Install python3 in operating systems based on Debian.
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install python3
# Install python3 in operating systems based on ArchLinux
$ sudo pacman -Sy python
# Finally check the installed version
$ python --version
```

License
----

GNU Lesser General Public License v3.0

Oh Yeah! Free Software,  it's great, enjoy!
