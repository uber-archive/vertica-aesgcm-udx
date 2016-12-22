\set libfile '\''`pwd`'/aesgcm.so\''

-- Install the library with a test prefix.
CREATE OR REPLACE LIBRARY TEST_AESGCM AS :libfile;
CREATE OR REPLACE FUNCTION TEST_AESGCM_Decrypt AS LANGUAGE 'C++' NAME 'AESGCMDecryptFactory' LIBRARY TEST_AESGCM;
CREATE OR REPLACE FUNCTION TEST_AESGCM_Decrypt AS LANGUAGE 'C++' NAME 'AESGCMDecryptWithVarcharADFactory' LIBRARY TEST_AESGCM;
CREATE OR REPLACE FUNCTION TEST_AESGCM_Decrypt AS LANGUAGE 'C++' NAME 'AESGCMDecryptWithVarbinaryADFactory' LIBRARY TEST_AESGCM;
CREATE OR REPLACE FUNCTION TEST_AESGCM_Encrypt AS LANGUAGE 'C++' NAME 'AESGCMEncryptFactory' LIBRARY TEST_AESGCM;
CREATE OR REPLACE FUNCTION TEST_AESGCM_Encrypt AS LANGUAGE 'C++' NAME 'AESGCMEncryptWithVarcharADFactory' LIBRARY TEST_AESGCM;
CREATE OR REPLACE FUNCTION TEST_AESGCM_Encrypt AS LANGUAGE 'C++' NAME 'AESGCMEncryptWithVarbinaryADFactory' LIBRARY TEST_AESGCM;

-- Global variables.
\set keyfile        '\''`pwd`'/test-key.hex\''
\set plaintext      '\'hello\''
\set ciphertext     'HEX_TO_BINARY(''0x30313233343536373839414215c760f2a1ba7ee1b4401f142642105137b10b25a0'')' -- :plaintext encrypted with :keyfile, nonce prefixed.
\set aad            '\'length:5\'' -- example additional associated data for :plaintext.
\set aad_bin        'HEX_TO_BINARY(''0x6c656e6774683a35'')' -- :aad in hexadecimal.
\set ciphertext_aad 'HEX_TO_BINARY(''0x465efaf742f5e4d68d5188f3808aad3a140ed47210ad7a3886ad8ebf89defd8778'')' -- :plaintext encrypted with :keyfile and :aad (or :aad_binary), nonce prefixed.

-- Test harness variables. Note that :expected should never fail to evaluate, otherwise tests are difficult to debug.
\set test_header 'SELECT ''TESTCASE'' AS testcase, :description AS description, :expected AS expected, :error_expected AS error_expected'
\set run_test    ':test_header; SELECT :expression'

-- Positive test cases.
\set error_expected 'false'

\set description '\'ciphertext has expected length\''
\set expression  'LENGTH(TEST_AESGCM_Encrypt(:plaintext USING PARAMETERS key=:keyfile))'
\set expected    'LENGTH(:plaintext) + 12 + 16'
:run_test;

\set description '\'encrypt an empty string\''
\set expression  'LENGTH(TEST_AESGCM_Encrypt('''' USING PARAMETERS key=:keyfile))'
\set expected    '12+16'
:run_test;

\set description '\'encrypting NULL returns NULL\''
\set expression  'TEST_AESGCM_Encrypt(NULL USING PARAMETERS key=:keyfile) IS NULL'
\set expected    'true'
:run_test;

\set description '\'nested encryption and decryption\''
\set expression  'TEST_AESGCM_Decrypt(TEST_AESGCM_Encrypt(:plaintext USING PARAMETERS key=:keyfile) USING PARAMETERS key=:keyfile)'
\set expected    ':plaintext'
:run_test;

\set description '\'decrypting NULL returns NULL\''
\set expression  'TEST_AESGCM_Decrypt(NULL USING PARAMETERS key=:keyfile) IS NULL'
\set expected    'true'
:run_test;

\set description '\'decrypting ciphertext yields expected plaintext\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext USING PARAMETERS key=:keyfile)'
\set expected    ':plaintext'
:run_test;

\set description '\'encrypting is volatile\''
\set expression  'COUNT(DISTINCT TEST_AESGCM_Encrypt(plaintext USING PARAMETERS key=:keyfile)) FROM (SELECT :plaintext AS plaintext UNION ALL SELECT :plaintext) AS plaintexts'
\set expected    '2'
:run_test;

\set description '\'decrypting is stable\''
\set expression  'COUNT(DISTINCT TEST_AESGCM_Decrypt(ciphertext USING PARAMETERS key=:keyfile)) FROM (SELECT :ciphertext AS ciphertext UNION ALL SELECT :ciphertext) AS ciphertexts'
\set expected    '1'
:run_test;

\set description '\'encrypting with associated data stored as VARCHAR\''
\set expression  'LENGTH(TEST_AESGCM_Encrypt(:plaintext, :aad USING PARAMETERS key=:keyfile))'
\set expected    'LENGTH(:plaintext) + 12 + 16'
:run_test;

\set description '\'encrypting with associated data stored as VARBINARY\''
\set expression  'LENGTH(TEST_AESGCM_Encrypt(:plaintext, :aad_bin USING PARAMETERS key=:keyfile))'
\set expected    'LENGTH(:plaintext) + 12 + 16'
:run_test;

\set description '\'decrypting with associated data stored as VARCHAR or VARBINARY yields the same result\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext_aad, :aad_bin USING PARAMETERS key=:keyfile) = TEST_AESGCM_Decrypt(:ciphertext_aad, :aad USING PARAMETERS key=:keyfile)'
\set expected    'true'
:run_test;

\set description '\'encrypting with NULL associated data\''
\set expression  'LENGTH(TEST_AESGCM_Encrypt(:plaintext, NULL USING PARAMETERS key=:keyfile))'
\set expected    'LENGTH(:plaintext) + 12 + 16'
:run_test;

\set description '\'decrypting with either NULL or absent associated data is identical\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext, NULL USING PARAMETERS key=:keyfile) = TEST_AESGCM_Decrypt(:ciphertext USING PARAMETERS key=:keyfile)'
\set expected    'true'
:run_test;

\set description '\'decrypting with either empty string or absent associated data is identical\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext, '''' USING PARAMETERS key=:keyfile) = TEST_AESGCM_Decrypt(:ciphertext USING PARAMETERS key=:keyfile)'
\set expected    'true'
:run_test;

\set description '\'nested encryption and decryption with associated data\''
\set expression  'TEST_AESGCM_Decrypt(TEST_AESGCM_Encrypt(:plaintext, :aad USING PARAMETERS key=:keyfile), :aad USING PARAMETERS key=:keyfile)'
\set expected    ':plaintext'
:run_test;

\set description '\'nested encryption and decryption with empty associated data\''
\set expression  'TEST_AESGCM_Decrypt(TEST_AESGCM_Encrypt(:plaintext, '''' USING PARAMETERS key=:keyfile), NULL USING PARAMETERS key=:keyfile)'
\set expected    ':plaintext'
:run_test;

-- Negative test cases.
\set error_expected 'true' -- all of these tests produce ERRORs.
\set expected       'NULL' -- not used for negative tests.

\set description '\'fail to encrypt a non-VARCHAR column\''
\set expression  'TEST_AESGCM_Encrypt(42 USING PARAMETERS key=:keyfile)'
:run_test;

\set description '\'fail to encrypt with no parameters specified\''
\set expression  'TEST_AESGCM_Encrypt(:plaintext)'
:run_test;

\set description '\'fail to encrypt with an invalid keyfile\''
\set expression  'TEST_AESGCM_Encrypt(:plaintext USING PARAMETERS key=''/dev/null'')'
:run_test;

\set description '\'fail to decrypt a non-VARBINARY column\''
\set expression  'TEST_AESGCM_Decrypt(42 USING PARAMETERS key=:keyfile)'
:run_test;

\set description '\'test decrypt with no parameters\''
\set expression  'TEST_AESGCM_Decrypt(''hello'')'
:run_test;

\set description '\'fail to decrypt a ciphertext that is too short\''
\set expression  'TEST_AESGCM_Decrypt(HEX_TO_BINARY(''0xDEADBEEF'') USING PARAMETERS key=:keyfile)'
:run_test;

\set description '\'fail to decrypt using the wrong key\''
\set expression  'TEST_AESGCM_Decrypt(HEX_TO_BINARY(''0xFFFFFFFFFFFFFFFFFFFFFFFFFF'') USING PARAMETERS key=:keyfile)'
:run_test;

\set description '\'fail to decrypt with an invalid keyfile\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext USING PARAMETERS key=''/dev/null'')'
:run_test;

\set description '\'fail to encrypt with incorrect type for AAD\''
\set expression  'TEST_AESGCM_Encrypt(:plaintext, 42 USING PARAMETERS key=:keyfile)'
:run_test;

\set description '\'fail to decrypt with incorrect type for AAD\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext_aad, 42 USING PARAMETERS key=:keyfile)'
:run_test;

\set description '\'fail to verify ciphertext with incorrect AAD\''
\set expression  'TEST_AESGCM_Decrypt(:ciphertext_aad, ''bad'' USING PARAMETERS key=:keyfile)'
:run_test;

-- Uninstall the test-prefix library.
DROP LIBRARY TEST_AESGCM CASCADE;
