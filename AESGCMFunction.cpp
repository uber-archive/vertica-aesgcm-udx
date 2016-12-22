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

#include <fstream>
#include <iomanip>

using namespace Vertica;

// readKeyFile reads an AES256 key from the file stored at key_path from the
// local filesystem. The key is expected to be stored as hexadecimal ASCII
// (i.e. using only characters 0-9a-fA-F). The 256-bit value of the key is
// stored in key_out. If a 256-bit key was successfully read, this function
// returns true.  If there are any errors, key_out may be partially or
// incorrectly set.
bool readKeyFile(const std::string &key_path,
    unsigned char key_out[crypto_aead_aes256gcm_KEYBYTES]) {
    // Each "byte" of key is two bytes of hex.
    // std::setw accounts for a NULL-terminating character.
    static const size_t key_hex_length = (crypto_aead_aes256gcm_KEYBYTES * 2) + 1;
    char key_hex[key_hex_length];
    std::ifstream key_file(key_path.c_str());
    return (key_file >> std::setw(key_hex_length) >> key_hex) &&
        sodium_hex2bin(key_out, crypto_aead_aes256gcm_KEYBYTES, key_hex, key_hex_length,
                NULL, NULL, NULL) == 0;
}

const long int AESGCMFunction::overhead = crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_ABYTES;

void AESGCMFunction::setup(ServerInterface &srvInterface,
        const SizedColumnTypes &argTypes) {
    if (argTypes.getColumnCount() < 1 || argTypes.getColumnCount() > 2) {
        vt_report_error(0, "Function accepts either 1 or 2 arguments, but %zu provided",
                argTypes.getColumnCount());
    }

    column_name = argTypes.getColumnName(0);

    ParamReader paramReader = srvInterface.getParamReader();
    if (!paramReader.containsParameter(KEY_PATH_PARAM)) {
        vt_report_error(0, "Required parameter \"" KEY_PATH_PARAM  "\" missing");
    }

    std::string key_path = paramReader.getStringRef(KEY_PATH_PARAM).str();
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

    if (!readKeyFile(key_path, key)) {
        vt_report_error(0, "Failed to read key from file: %s", key_path.c_str());
    }

    sodium_init();

    if (!crypto_aead_aes256gcm_is_available()) {
        vt_report_error(0, "System support required for AES256-GCM is unavailable");
    }

    crypto_aead_aes256gcm_beforenm(&crypto_ctx, key);
}

void AESGCMFunctionFactory::getParameterType(ServerInterface &srvInterface,
        SizedColumnTypes &parameterTypes) {
    static const SizedColumnTypes::Properties key_props(
            true, // Visible
            true, // Required
            false, // Can be NULL
            "Specifies the path to a file containing a 256-bit AES key in hexadecimal representation." // Comment
        );
    parameterTypes.addVarchar(MAX_KEY_PATH, KEY_PATH_PARAM, key_props);
}

void AESGCMFunctionFactory::getPerInstanceResources(ServerInterface &srvInterface,
        VResources &res) {
    // Each AESGCMFunction instance opens a single file to read the key.
    res.nFileHandles += 1;
}
