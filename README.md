# What is this?

This is a small and simple pure-Go library for symmetric and asymmetric encryption using Elliptic Curve Cryptography (ECC).

# Why?

I needed such a library for another project and decided to post this one here, if someone else needs such a "simple" library.

# How to use?

1. Create a string seed for generating the elliptic curve.
2. Pass the seed to the New function.
3. Use AssymetricEncrypt function to encrypt a text up to 64 bytes.
4. Use AssymetricDecrypt function to decrypt the encrypted text.
5. Use SymmetricEncrypt to encrypt a text message with random length. The function will automatically generate a random key for the encryption process and will return it as a parameter.
6. Use SymmetricDecrypt with the encrypted value and the key to decrypt the message above.

There are two test function, which can be used to test the source code's functionality:
- TestSymmetricEncryption
- TestAssymetricEncryption

# Why can't I pass a key to the symmetric encryption?

Well, the idea is to generate a private-public key pair. Then encrypt your long message with the symmetric function and then encrypt the key used for the symmetric encryption with your public key.

In order to decrypt the data, you need your private key to get your symmetric key and from there you can decrypt your long message.

# Disclaimer

I've developed this library out of my personal needs and I am sharing it for everyone, who this could be useful to. I carry no responsibility, what this library is being used for and if the usage of it causes any harm, damage or data loss. Its usage is sole responsibility of the user!

# License

Copyright 2020 Mihail Milev

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
