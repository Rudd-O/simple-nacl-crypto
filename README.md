# simple-nacl-crypto: two programs to encrypt and decrypt files using NaCL secretbox

This is very straightforward and nothing fancy.  It's two programs to encrypt and decrypt files on disk that use NaCL authenticated encryption implemented in `secretbox`.

Do not use this.  It is unsafe to use.  The key is not hashed.  That makes it trivial to crack your encrypted files unless you know what you are doing.

You have been warned.

## Building and testing

In the checkout directory, type:

        make

This builds the programs.  Now you can run `bin/nacl-encrypt` and `bin/nacl-decrypt` to your heart's content.

## Technical data

The encryption format is very simple:

* 16 bytes for the header which is simply a random nonce
* a chain of zero or more packets composed of two fields:
  * 8 bytes for the length of the following packet
  * n bytes for the packet itself

Each packet contains n - 16 bytes of data, encrypted using NaCL secretboxes.
Each packet is also generated with an unique nonce derived from the nonce
header and a simple incrementing number.
