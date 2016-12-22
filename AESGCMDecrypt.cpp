// Copyright (c) 2016 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "AESGCMFunction.h"

#include <Vertica.h>
#include <sodium.h>

using namespace Vertica;

// AESGCMDecrypt provides a Vertica Scalar Function for decrypting AES-GCM
// authenticated encryption with associated data (AEAD) stored in VARBINARY
// columns. It is the counterpart to AESGCMEncrypt.
//
// Note that the nonce for decryption is supplied as a 96 bit (12 byte) prefix
// to the ciphertext. The result will thus be 28 bytes shorter (12
// byte nonce + 16 byte associated data tag).
//
// The result column type is always a VARCHAR(X), where given an input column
// VARBINARY(Y), X = Y - 28. See AESGCMDecryptFactory.
class AESGCMDecrypt: public AESGCMFunction {
    public:
        virtual void processBlock(ServerInterface &srvInterface,
                BlockReader &arg_reader,
                BlockWriter &res_writer) {
            if (arg_reader.getNumCols() < 1 || arg_reader.getNumCols() > 2) {
                vt_report_error(0, "Function accepts either 1 or 2 arguments, but %zu provided",
                        arg_reader.getNumCols());
            }

            do {
                if (arg_reader.isNull(0)) {
                    // Decrypting NULL returns NULL.
                    res_writer.getStringRef().setNull();
                    res_writer.next();
                    continue;
                }

                VString nonce_and_ciphertext = arg_reader.getStringRef(0);

                const unsigned char *associated_data = NULL;
                size_t associated_data_length = 0;
                if (arg_reader.getNumCols() > 1 && !arg_reader.isNull(1)) {
                    VString ad = arg_reader.getStringRef(1);
                    associated_data_length = ad.length();
                    if (associated_data_length > 0) {
                        associated_data = (unsigned char *)ad.data();
                    }
                }

                VString &plaintext = res_writer.getStringRef();

                if (nonce_and_ciphertext.length() < overhead) {
                    vt_report_error(0,
                            "Ciphertext in column '%s' is too short (%zu) expected at least %zu",
                            column_name.c_str(),
                            nonce_and_ciphertext.length(),
                            overhead);
                }

                plaintext.alloc(nonce_and_ciphertext.length() - overhead);

                long long unsigned int plaintext_length = 0;

                const unsigned char *nonce = (unsigned char *)nonce_and_ciphertext.data();
                const unsigned char *ciphertext =
                    (unsigned char *)nonce_and_ciphertext.data() + crypto_aead_aes256gcm_NPUBBYTES;
                size_t ciphertext_length =
                    nonce_and_ciphertext.length() - crypto_aead_aes256gcm_NPUBBYTES;

                int decrypt_res = crypto_aead_aes256gcm_decrypt_afternm(
                        (unsigned char *)plaintext.data(), &plaintext_length,
                        NULL, // unused, always NULL
                        ciphertext, ciphertext_length,
                        associated_data, associated_data_length,
                        nonce, &crypto_ctx);

                if (decrypt_res == -1) {
                    vt_report_error(0, "Failed to verify ciphertext in column '%s'", column_name.c_str());
                } else if (decrypt_res != 0) {
                    vt_report_error(0, "Error encountered during decryption of column '%s'", column_name.c_str());
                }

                res_writer.next();
            } while (arg_reader.next());
        }
};

// Exposes a scalar function taking as input VARBINARY and producing VARCHAR.
// See AESGCMDecrypt.
class AESGCMDecryptFactory: public AESGCMFunctionFactory {
    public:
        AESGCMDecryptFactory() {
            // For some given arguments, the results yielded are the same for
            // the duration of the statement. For example the encryption keys
            // could change between statements.
            vol = STABLE;
        }

        virtual ScalarFunction *createScalarFunction(ServerInterface &server) {
            return vt_createFuncObj(server.allocator, AESGCMDecrypt);
        }

        virtual void getPrototype(ServerInterface &server,
                ColumnTypes &argTypes,
                ColumnTypes &returnType) {
            argTypes.addVarbinary();
            returnType.addVarchar();
        }

        virtual void getReturnType(ServerInterface &server,
                const SizedColumnTypes &argTypes,
                SizedColumnTypes &returnType) {
            const VerticaType &t = argTypes.getColumnType(0);
            int length = t.getStringLength() - AESGCMDecrypt::overhead;
            // Length of a string in a return type must be greater than zero.
            returnType.addVarchar(length > 0 ? length : 1);
        }
};

RegisterFactory(AESGCMDecryptFactory);

// Exposes a scalar function taking as input VARBINARY as well as VARCHAR
// associated data and producing VARCHAR. See AESGCMDecrypt.
class AESGCMDecryptWithVarcharADFactory: public AESGCMDecryptFactory {
    public:
        virtual void getPrototype(ServerInterface &server,
                ColumnTypes &argTypes,
                ColumnTypes &returnType) {
            argTypes.addVarbinary();
            argTypes.addVarchar();
            returnType.addVarchar();
        }
};

RegisterFactory(AESGCMDecryptWithVarcharADFactory);

// Exposes a scalar function taking as input VARBINARY as well as VARBINARY
// associated data and producing VARCHAR. See AESGCMDecrypt.
class AESGCMDecryptWithVarbinaryADFactory: public AESGCMDecryptFactory {
    public:
        virtual void getPrototype(ServerInterface &server,
                ColumnTypes &argTypes,
                ColumnTypes &returnType) {
            argTypes.addVarbinary();
            argTypes.addVarbinary();
            returnType.addVarchar();
        }
};

RegisterFactory(AESGCMDecryptWithVarbinaryADFactory);
