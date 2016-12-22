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
#include <cstring>

using namespace Vertica;

// AESGCMEncrypt provides a Vertica Scalar Function for encrypting plaintext
// stored in VARCHAR with 256-bit AES-GCM authenticated encryption with
// associated data (AEAD). It is the counterpart to AESGCMDecrypt.
//
// A 96-bit (12 byte) nonce is generated at encryption time and prefixed to the
// output ciphertext. The ciphertext is an additional 16 bytes longer than the
// plaintext to account for the associated data tag. Thus the result ciphertext
// is in total 28 bytes longer than the plaintext.
//
// The result column type is always a VARBINARY(X), where given an input column
// VARCHAR(Y), X = Y + 28. See AESGCMEncryptFactory.
class AESGCMEncrypt: public AESGCMFunction
{
    public:
        virtual void processBlock(ServerInterface &srvInterface,
                BlockReader &arg_reader,
                BlockWriter &res_writer) {
            if (arg_reader.getNumCols() < 1 || arg_reader.getNumCols() > 2) {
                vt_report_error(0, "Function accepts either 1 or 2 arguments, but %zu provided",
                        arg_reader.getNumCols());
            }

            // Generate a nonce to be reused for duration of this call. The
            // nonce is incremented after each encrypt.
            unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
            randombytes_buf(nonce, sizeof(nonce));

            do {
                if (arg_reader.isNull(0)) {
                    // Encrypting NULL returns NULL.
                    res_writer.getStringRef().setNull();
                    res_writer.next();
                    continue;
                }

                VString plaintext = arg_reader.getStringRef(0);

                const unsigned char *associated_data = NULL;
                size_t associated_data_length = 0;
                if (arg_reader.getNumCols() > 1 && !arg_reader.isNull(1)) {
                    VString ad = arg_reader.getStringRef(1);
                    associated_data_length = ad.length();
                    if (associated_data_length > 0) {
                        associated_data = (unsigned char *)ad.data();
                    }
                }

                VString &nonce_and_ciphertext = res_writer.getStringRef();

                nonce_and_ciphertext.alloc(plaintext.length() + overhead);

                memcpy((unsigned char *)nonce_and_ciphertext.data(), nonce, sizeof(nonce));

                long long unsigned int ciphertext_length = 0;
                unsigned char *ciphertext =
                    (unsigned char *)nonce_and_ciphertext.data() + crypto_aead_aes256gcm_NPUBBYTES;

                crypto_aead_aes256gcm_encrypt_afternm(
                        ciphertext, &ciphertext_length,
                        (const unsigned char *)plaintext.data(), plaintext.length(),
                        associated_data, associated_data_length,
                        NULL, // unused, always NULL
                        nonce, &crypto_ctx);

                sodium_increment(nonce, crypto_aead_aes256gcm_NPUBBYTES);

                res_writer.next();
            } while (arg_reader.next());
        }
};

// Exposes a scalar function taking as input VARCHAR and producing VARBINARY.
// See AESGCMEncrypt.
class AESGCMEncryptFactory: public AESGCMFunctionFactory
{
    public:
        AESGCMEncryptFactory() {
            // For some given arguments, the results yielded are unique for
            // the duration of the statement. The nonce generated should be
            // different each invocation within a statement.
            vol = VOLATILE;
        }

        virtual ScalarFunction *createScalarFunction(ServerInterface &server) {
            return vt_createFuncObj(server.allocator, AESGCMEncrypt);
        }

        virtual void getPrototype(ServerInterface &server,
                ColumnTypes &argTypes,
                ColumnTypes &returnType) {
            argTypes.addVarchar();
            returnType.addVarbinary();
        }

        virtual void getReturnType(ServerInterface &server,
                const SizedColumnTypes &argTypes,
                SizedColumnTypes &returnType) {
            const VerticaType &t = argTypes.getColumnType(0);
            returnType.addVarbinary(t.getStringLength() + AESGCMEncrypt::overhead);
        }
};

RegisterFactory(AESGCMEncryptFactory);

// Exposes a scalar function taking as input VARCHAR as well as VARCHAR
// associated data and producing VARBINARY. See AESGCMEncrypt.
class AESGCMEncryptWithVarcharADFactory: public AESGCMEncryptFactory {
    public:
        virtual void getPrototype(ServerInterface &server,
                ColumnTypes &argTypes,
                ColumnTypes &returnType) {
            argTypes.addVarchar();
            argTypes.addVarchar();
            returnType.addVarbinary();
        }
};

RegisterFactory(AESGCMEncryptWithVarcharADFactory);

// Exposes a scalar function taking as input VARCHAR as well as VARBINARY
// associated data and producing VARBINARY. See AESGCMEncrypt.
class AESGCMEncryptWithVarbinaryADFactory: public AESGCMEncryptFactory {
    public:
        virtual void getPrototype(ServerInterface &server,
                ColumnTypes &argTypes,
                ColumnTypes &returnType) {
            argTypes.addVarchar();
            argTypes.addVarbinary();
            returnType.addVarbinary();
        }
};

RegisterFactory(AESGCMEncryptWithVarbinaryADFactory);
