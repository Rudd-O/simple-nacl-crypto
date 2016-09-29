# simple-nacl-crypto: encrypt and decrypt files using NaCL secretbox

This is very straightforward and nothing fancy:

* A program `nacl-crypt` to encrypt and decrypt files on disk, using NaCL
  authenticated encryption implemented in `secretbox`.
* A library that lets you implement "streaming" encryption of data, as
  well as an efficient encoding of sparse data (as in "files with holes").

This has not been reviewed.  The key is not hashed either.  That makes it
trivial for an attacker to crack your encrypted files, unless you know
what you are doing.  If "unless you know what you are doing" baffles you,
you do not know what you are doing.

That said, enjoy.

## Building and testing

In the checkout directory, type:

        make

This builds the program.  Now, to run the tests, type:

        make test

## Using the command line utility

Run the program `bin/nacl-crypt`.

Here's how you encrypt a file F to a file G, using the key "abc":

        bin/nacl-crypt enc F G abc

If the file you are encrypting has holes (i.e. it's sparse) you can save
some (potentially an enormous) amount of disk space by passing the flag
`-s` to `nacl-crypt enc`:

        bin/nacl-crypt -s enc F G abc

Here is how you decrypt the G file to a file Fprime, using the same key:

        bin/nacl-crypt G Fprime abc

### Buffer sizes and efficiency

The size of the packets written by the `EncryptedSerializer` depends
on the size of the buffer passed to its `Read()` method.  The normal
`io.Copy()` size appears to be 32 KB.  This leads to some inefficiency.
A similar situation occurs with the `SparseEncoder`, which causes it
to fail to detect long runs of zeroes on its input stream.

This is easily fixable by wrapping the `EncryptedSerializer` in a
`bufio.Reader` with a large buffer size.

Note that the `EncryptedDeserializer` will refuse to decode an encrypted
file that was created with packets larger than the size passed to its
constructor, to prevent malicious attackers who may have tampered with
the encrypted files from causing huge memory allocations on the computer
running the decryptor.

By default, the buffer size in the command line utility is 1 MiB.  If
you need to decrypt files that were created with a larger buffer size
(the command line utility will tell you very loudly it can't do it)
you can use the flag `-b` to specify a size in bytes.

## Technical data about the file format

The encryption format is very simple:

* 16 bytes for the header which is simply a random nonce
* 1 packet composed of two fields
  * 8 bytes for the length of the packet to follow
  * 24 bytes for the packet itself
    * 16 bytes of overhead written
    * 4 bytes with the nacl.Secretbox payload, encrypted
      * 4 bytes that indicate:
        * 1 if the encrypted contents are sparsified
        * 0 if the encrypted contents are not sparsified
* a chain of zero or more packets composed of two fields
  * 8 bytes for the length of the packet to follow
  * n bytes for the packet itself
    * 16 bytes of overhead written by nacl.Secretbox
    * n - 16 bytes with the nacl.Secretbox payload, encrypted
      * 8 bytes that indicate:
        * if the high bit is set, number of blocks to skip on output
        * else, number of bytes of data to write
      * 0 to n bytes with the data to write
        (0 is only allowed if the previous 8 bytes had the high bit set)

The nacl.Secretbox payloads are encrypted using NaCL secretboxes.
Each payload is generated with an unique nonce derived from the nonce
header and a simple incrementing number.
