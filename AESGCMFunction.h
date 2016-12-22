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

#ifndef AESGCMFUNCTION_H_INCLUDED
#define AESGCMFUNCTION_H_INCLUDED

#include <Vertica.h>
#include <sodium.h>

#include <string>
#include <limits.h>

#define VERTICA_VARCHAR_MAX 65000
#if defined(PATH_MAX)&&(PATH_MAX<=VERTICA_VARCHAR_MAX)
#   define MAX_KEY_PATH PATH_MAX
#else
#   define MAX_KEY_PATH VERTICA_VARCHAR_MAX
#endif

#define KEY_PATH_PARAM "key"

// AESGCMFunction encapsulates key reading functionality common to the
// encryption and decryption scalar functions. The key is read from a file
// specified by a function parameter (KEY_PATH_PARAM).
class AESGCMFunction: public Vertica::ScalarFunction {
    protected:
        crypto_aead_aes256gcm_state crypto_ctx;
        std::string column_name;

    public:
        // The maximum number of bytes added to the length of the plaintext to
        // accomodate the public nonce and additional data tag.
        static const long int overhead;

        virtual void setup(Vertica::ServerInterface &srvInterface,
                const Vertica::SizedColumnTypes &argTypes);
};

// AESGCMFunctionFactory provides metainformation common to
// AESGCMEncryptFactory and AESGCMDecryptFactory, namely volatility, stability,
// and parameter hints.
class AESGCMFunctionFactory: public Vertica::ScalarFunctionFactory {
    public:
        virtual void getParameterType(Vertica::ServerInterface &srvInterface,
                Vertica::SizedColumnTypes &parameterTypes);
        virtual void getPerInstanceResources(Vertica::ServerInterface &srvInterface,
                Vertica::VResources &res);
};

#endif /* AESGCMFUNCTION_H_INCLUDED */
