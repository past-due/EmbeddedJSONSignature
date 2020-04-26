/*
	EmbeddedJSONSignature - v1.0

	Copyright (c) 2020 past-due (https://github.com/past-due)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#ifndef _EMBEDDED_JSON_SIGNATURE_H_
#define _EMBEDDED_JSON_SIGNATURE_H_

#include <string>
#include <vector>

// Implement a simple embedded JSON signature algorithm
//
// Signing:
// - take a valid JSON object (as a string)
// - compute the digital signature of the entire JSON object string, as-is
// - embed the digital signature *immediately* after the opening "{",
//   as a valid key/value pair with key "SIGNATURE", value "<base64 of signature>", and a trailing comma
// The output is a valid JSON object which embeds its own signature, assuming the input JSON object has at least one key/value pair.
//
// Verifying:
// - take a JSON object string
// - find and extract the "SIGNATURE" key/value pair that occurs immediately after the opening "{" (through its trailing comma)
//   - yielding: (1) the original JSON object string (before signing) & (2) the SIGNATURE key/value pair
// - verify the digital signature on the *original* JSON object string
//
// Example:
//	- original json:
//		{
//			"example key": "example value"
//		}
//	- signed json output:
//		{"SIGNATURE":"<signature base64>",
//			"example key": "example value"
//		}
//
// Notes:
//	- The validity of the signature is dependent upon the output JSON object maintaining its byte-for-byte form.
//	  i.e.
//		Acceptable transformations of output JSON:
//		- Lossless compression & decompression (ex. gzip)
//		Not acceptable (will break the signature):
//		- Minifying / reformatting / manipulating whitespace / etc
//	- Apply any formatting / minifying / etc *before* signing.
//
class EmbeddedJSONSignature {
public:
	// Signs a JSON object, returning the JSON object with a signature embedded (as a prepended "SIGNATURE" key/value pair)
	// The output is still a valid JSON object, assuming the input JSON object has at least one key/value pair.
	//
	// Requires a secret key compatible with libsodium's "public-key-signature" functions
	//
	// To generate a new signing keypair, see `crypto_sign_keypair`:
	// - https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures#key-pair-generation
	static std::string signJson(const std::string& originalJson, const std::string& base64SecretKey);
	static std::string signJson(const std::string& originalJson, const std::vector<unsigned char>& secretKeyBytes);

	// Verifies a JSON object signed by `signJson`
	// Sets `output_originalJson` to the original JSON object that was signed (i.e. minus the prepended "SIGNATURE" key/value pair)
	// Returns `true` if a signature was found and is valid
	//
	// Requires a public key compatible with libsodium's "public-key-signature" functions
	static bool verifySignedJson(const std::string& signedJson, const std::string& base64PublicKey, std::string& output_originalJson);
	static bool verifySignedJson(const std::string& signedJson, const std::vector<unsigned char>& publicKeyBytes, std::string& output_originalJson);
	static bool verifySignedJson(const char *signedJson, size_t signedJsonLen, const std::string& base64PublicKey, std::string& output_originalJson);
	static bool verifySignedJson(const char *signedJson, size_t signedJsonLen, const std::vector<unsigned char>& publicKeyBytes, std::string& output_originalJson);
public:
	// Base64 helpers
	static std::string b64Encode(const std::vector<unsigned char> &bytes);
	static std::vector<unsigned char> b64Decode(const std::string &str);
};

#endif //_EMBEDDED_JSON_SIGNATURE_H_
