# simple-nacl-crypto: two programs to encrypt and decrypt files using NaCL secretbox

This is very straightforward and nothing fancy.  It's two programs to encrypt and decrypt files on disk that use NaCL authenticated encryption implemented in `secretbox`.

Do not use this.  It is unsafe to use.  The key is not hashed.  That makes it trivial to crack your encrypted files unless you know what you are doing.

You have been warned.
