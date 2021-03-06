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

#include "EmbeddedJSONSignature.h"
#include <sodium.h>
#include <stdexcept>
#include <string.h>
#include <algorithm>

std::string EmbeddedJSONSignature::b64Encode(const std::vector<unsigned char> &bytes)
{
	if (bytes.empty())
	{
		return "";
	}
	size_t encodedBytesRequired = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL); // includes null terminator
	std::vector<char> encodedChars(encodedBytesRequired, '\0');
	if (sodium_bin2base64(encodedChars.data(), encodedChars.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL) == nullptr)
	{
		// sodium_bin2base64 failed
		return "";
	}
	if (encodedChars.back() == '\0')
	{
		encodedChars.pop_back();
	}
	return std::string(encodedChars.begin(), encodedChars.end());
}

std::vector<unsigned char> EmbeddedJSONSignature::b64Decode(const std::string &str)
{
	if (str.empty())
	{
		return {};
	}
	size_t binaryMaxLen = str.size();
	size_t binaryLen = 0;
	std::vector<unsigned char> bytes(binaryMaxLen, '\0');
	if (sodium_base642bin(reinterpret_cast<unsigned char *>(bytes.data()), bytes.size(), str.c_str(), str.size(), nullptr, &binaryLen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0)
	{
		// sodium_base642bin failed
		return {};
	}
	bytes.resize(binaryLen);
	return bytes;
}

static const char JSON_SIGNATURE_KEY[] = "SIGNATURE";

std::string EmbeddedJSONSignature::signJson(const std::string& originalJson, const std::string& base64SecretKey)
{
	const auto sk = b64Decode(base64SecretKey);
	return signJson(originalJson, sk);
}

std::string EmbeddedJSONSignature::signJson(const std::string& originalJson, const std::vector<unsigned char>& secretKeyBytes)
{
	if (originalJson.empty())
	{
		throw std::runtime_error("Input json is empty");
	}
	if (originalJson.front() != '{')
	{
		throw std::runtime_error("Input json is not an object - must start with '{'");
	}
	if (secretKeyBytes.size() != crypto_sign_SECRETKEYBYTES)
	{
		std::string errorStr = "Invalid length of secretKeyBytes - expecting " + std::to_string(crypto_sign_SECRETKEYBYTES) + ", received " + std::to_string(secretKeyBytes.size());
		throw std::runtime_error(errorStr);
	}

	std::vector<unsigned char> sig(crypto_sign_BYTES, '\0');

	if (crypto_sign_detached(sig.data(), nullptr, (const unsigned char *)originalJson.c_str(), static_cast<unsigned long long>(originalJson.size()), secretKeyBytes.data()) != 0)
	{
		// crypto_sign_detached failed
		throw std::runtime_error("crypto_sign_detached failed");
	}

	// double-check verify signature
	std::vector<unsigned char> publickey(crypto_sign_PUBLICKEYBYTES, '\0');
	crypto_sign_ed25519_sk_to_pk(publickey.data(), secretKeyBytes.data());
	if (crypto_sign_verify_detached(sig.data(), (const unsigned char *)originalJson.c_str(), static_cast<unsigned long long>(originalJson.size()), publickey.data()) != 0) {
		// Incorrect signature!
		throw std::runtime_error("Failed to verify signature generated by crypto_sign_detached");
	}

	// base64encode signature
	std::string b64Signature = b64Encode(sig);

	// prepend "SIGNATURE" key/value pair to very beginning of JSON object (immediately after opening '{')
	std::string resultJson = "{";
	resultJson += "\"";
	resultJson += JSON_SIGNATURE_KEY;
	resultJson += "\":\"";
	resultJson += b64Signature;
	resultJson += "\",";
	resultJson += originalJson.substr(1);
	return resultJson;
}

bool EmbeddedJSONSignature::verifySignedJson(const std::string& signedJson, const std::string& base64PublicKey, std::string& output_originalJson)
{
	const auto pk = b64Decode(base64PublicKey);
	return verifySignedJson(signedJson, pk, output_originalJson);
}

bool EmbeddedJSONSignature::verifySignedJson(const std::string& signedJson, const std::vector<unsigned char>& publicKeyBytes, std::string& output_originalJson)
{
	if (signedJson.empty())
	{
		throw std::runtime_error("Input json is empty");
	}
	return verifySignedJson(signedJson.c_str(), signedJson.size(), publicKeyBytes, output_originalJson);
}

bool EmbeddedJSONSignature::verifySignedJson(const char *signedJson, size_t signedJsonLen, const std::string& base64PublicKey, std::string& output_originalJson)
{
	const auto pk = b64Decode(base64PublicKey);
	return verifySignedJson(signedJson, signedJsonLen, pk, output_originalJson);
}

bool EmbeddedJSONSignature::verifySignedJson(const char *signedJson, size_t signedJsonLen, const std::vector<unsigned char>& publicKeyBytes, std::string& output_originalJson)
{
	if (!signedJson)
	{
		throw std::runtime_error("Input json is null");
	}
	if (signedJsonLen == 0)
	{
		throw std::runtime_error("Input json is empty");
	}
	if (*signedJson != '{')
	{
		throw std::runtime_error("Input json is not an object - must start with '{'");
	}
	if (publicKeyBytes.size() != crypto_sign_PUBLICKEYBYTES)
	{
		std::string errorStr = "Invalid length of publicKeyBytes - expecting " + std::to_string(crypto_sign_PUBLICKEYBYTES) + ", received " + std::to_string(publicKeyBytes.size());
		throw std::runtime_error(errorStr);
	}

	const std::string EmbeddedJSONSignaturePrefix = "{\"SIGNATURE\":\"";

	if (signedJsonLen < EmbeddedJSONSignaturePrefix.size() + 2 ) // {"SIGNATURE":"",
	{
		// Not enough room for even an *empty* signature
		return false;
	}

	const char* pCurrChar = signedJson;
	const char* const pSignedJsonEnd = pCurrChar + signedJsonLen;
	if (strncmp(pCurrChar, EmbeddedJSONSignaturePrefix.c_str(), EmbeddedJSONSignaturePrefix.size()) != 0)
	{
		// Failed to find prefix
		return false;
	}
	const char *pSignatureBegin = pCurrChar + EmbeddedJSONSignaturePrefix.size();
	const char *pSignatureEnd = std::find(pSignatureBegin, pSignedJsonEnd, '"');
	if (pSignatureEnd == pSignedJsonEnd)
	{
		return false;
	}
	const std::string base64Signature(pSignatureBegin, pSignatureEnd);
	const auto sig = b64Decode(base64Signature);
	if (sig.size() != crypto_sign_BYTES)
	{
		// Invalid signature length
		return false;
	}

	// Next char should be ','
	const char* pStartOriginalContent = pSignatureEnd + 1;
	if (pStartOriginalContent >= pSignedJsonEnd || *pStartOriginalContent++ != ',')
	{
		return false;
	}
	output_originalJson = "{";
	output_originalJson += std::string(pStartOriginalContent, pSignedJsonEnd);

	// Verify the signature
	if (crypto_sign_verify_detached(sig.data(), (const unsigned char *)output_originalJson.c_str(), static_cast<unsigned long long>(output_originalJson.size()), publicKeyBytes.data()) != 0) {
		// Incorrect signature!
		return false;
	}

	return true;
}
