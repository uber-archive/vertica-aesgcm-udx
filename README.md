AES-GCM UDx for Vertica
=======================

A User Defined Extension (UDx) for [Vertica](http://www.vertica.com) providing
scalar functions for 256-bit AES-GCM [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
and decryption with associated data.

The AES-GCM encryption and decryption implementations are provided by
[libsodium](https://download.libsodium.org/doc/).

This UDx has been tested with Vertica 7.2.3-13 and the Vertica 7.2.3 SDK.

Example Usage
-------------
Specify a 256-bit key in hexadecimal representation. For example:
```
$ echo 'AES256Key-32Characters1234567890' | xxd -pu -c 32 -l 32 >/tmp/my-key.hex
$ cat /tmp/my-key.hex
4145533235364b65792d33324368617261637465727331323334353637383930
```

Note that the key file must be local to Vertica (i.e. available on all nodes),
and the Vertica user must have read permissions. It is recommended to generate
a random key that uses the entire key space, unlike the ASCII example above.
For example:
```
$ dd if=/dev/urandom bs=32 count=1 | shasum -a256 -b | cut -d\  -f1 >a-good-random-key.hex
```

Encrypting a sample string:
```
=> WITH encrypted AS (SELECT AESGCM_Encrypt('hello' USING PARAMETERS key='/tmp/my-key.hex') AS ciphertext) SELECT ciphertext, TO_HEX(ciphertext) AS hex FROM encrypted;
-[ RECORD 1 ]---------------------------------------------------------------------------
ciphertext | o\310-/\031\363uu6\351\261\263l\3247\344[\267:s\222\305\2216+<P\314\031#(eq
hex        | 6fc82d2f19f3757536e9b1b36cd437e45bb73a7392c591362b3c50cc1923286571
```

Decrypting a hex string:
```
=> SELECT AESGCM_Decrypt(HEX_TO_BINARY('0x6fc82d2f19f3757536e9b1b36cd437e45bb73a7392c591362b3c50cc1923286571') USING PARAMETERS key='/tmp/my-key.hex') AS plaintext;
-[ RECORD 1 ]----
plaintext | hello
```

Additional associated data can also be provided to encrypt and decrypt. For
example, encrypting with additional associated data `length:5`:
```
=> WITH encrypted AS (SELECT AESGCM_Encrypt('hello', 'length:5' USING PARAMETERS key='/tmp/my-key.hex') AS ciphertext) SELECT ciphertext, TO_HEX(ciphertext) AS hex FROM encrypted;
-[ RECORD 1 ]---------------------------------------------------------------------------------------------------
ciphertext | \227f\224\326b\231\330\310\247a\270\365~\376\271W\001\347\251?\031{W\005\362\315Y\034\255A\316Q\357
hex        | 976694d66299d8c8a761b8f57efeb95701e7a93f197b5705f2cd591cad41ce51ef
```

The same associated data is then required to verify the ciphertext when
decrypting. Note that an error ("Failed to verify ciphertext") is produced when
the incorrect additional associated data is provided. In this example,
attempting to provide no (or empty) additional associated data result in an
error:
```
=> SELECT AESGCM_Decrypt(ciphertext USING PARAMETERS key='/tmp/my-key.hex') AS plaintext FROM (SELECT HEX_TO_BINARY('0x976694d66299d8c8a761b8f57efeb95701e7a93f197b5705f2cd591cad41ce51ef') AS ciphertext) AS example_table;
ERROR 3399:  Failure in UDx RPC call InvokeProcessBlock(): Error calling processBlock() in User Defined Object [AESGCM_Decrypt] at [AESGCMDecrypt.cpp:96], error code: 0, message: Failed to verify ciphertext in column ''
```

Providing the correct additional associated data results in successful
verification and decryption:
```
=> SELECT AESGCM_Decrypt(ciphertext, 'length:5' USING PARAMETERS key='/tmp/my-key.hex') AS plaintext FROM (SELECT HEX_TO_BINARY('0x976694d66299d8c8a761b8f57efeb95701e7a93f197b5705f2cd591cad41ce51ef') AS ciphertext) AS example_table;
-[ RECORD 1 ]----
plaintext | hello
```

Additional associated data can be provided as either `VARCHAR` or `VARBINRAY`.
Providing no associated data, or specifying `NULL` or an empty string are all
equivalent.

Encrypting or decrypting `NULL` values results in `NULL` values.

Implementation details
----------------------
The public 12-byte nonce is prefixed to the ciphertext.

With respect to the size of encrypted columns, there are 28 bytes of overhead
(12 bytes for the nonce, 16 bytes for the additional associated data tag).

See also the [libsodium AES-GCM documentation](https://download.libsodium.org/doc/secret-key_cryptography/aes-256-gcm.html)

Prerequisites
-------------
libsodium is provided through an external download. It is downloaded and
compiled during the build. The UDx library statically links to libsodium.

The Vertica SDK must be installed (default `/opt/vertica/sdk`). Alternative
locations can be specified using the `VERTICA_SDK` variable:
```
make VERTICA_SDK=/path/to/sdk
```

Installation
------------
To compile and install from a Vertica node:
```
make install-ddl
```

To pass flags to `vsql`, use the `VSQL_FLAGS` variable. E.g.:
```
make install-ddl VSQL_FLAGS='-U my_username -p 1234'
```

For more `make` targets see `make help`

Testing
-------
Running `make test` will execute a series of SQL queries against the local
Vertica instance (again, `VSQL_FLAGS` may be used to provide options to the
`vsql` invocation). Results are displayed to stdout.

Uninstallation
--------------
From a Vertica node:
```
make uninstall-ddl
```

License
-------
MIT License. See the `LICENSE` file for details.

