#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <wincrypt.h>

using namespace std;

DWORD getHash(const wstring& wsTargetPath, const ALG_ID algid, wstring& wsHash);

int main()
{
	wstring wsTargetPath{ L"C:\\Datas\\linuxmint-20.1-cinnamon-64bit.iso" };
	wcout << wsTargetPath << endl;
	wstring wsHash;
	ALG_ID algid[]{ CALG_MD5, CALG_SHA1, CALG_SHA_256, CALG_SHA_512 };
	wstring wsAlg[]{ L"MD5", L"SHA1", L"SHA-256", L"SHA-512" };
	for (int i = 0; i < sizeof(algid) / sizeof(algid[0]); ++i)
	{
		getHash(wsTargetPath, algid[i], wsHash);
		wcout << wsAlg[i] << L'\t' << wsHash << endl;
	}

	return 0;
}

DWORD getHash(const wstring& wsTargetPath, const ALG_ID algid, wstring& wsHash)
{
	switch (algid)
	{
	case CALG_MD5:
	case CALG_SHA1:
	case CALG_SHA_256:
	case CALG_SHA_512:
		break;
	default:
		return ERROR_BAD_ARGUMENTS;
	}

	ifstream ifs(wsTargetPath, ios::binary);
	if (!ifs)
		return ERROR_OPEN_FAILED;

	ifs.seekg(0, ios::end);
	size_t fbytes = ifs.tellg();
	ifs.seekg(ios::beg);

	PBYTE pContent = new BYTE[fbytes];
	ifs.read((char*)pContent, fbytes);

//--------------------------------------------------------------------
// Declare variables.
//
// hProv:           Handle to a cryptographic service provider (CSP). 
//                  This example retrieves the default provider for  
//                  the PROV_RSA_FULL provider type.  
// hHash:           Handle to the hash object needed to create a hash.
//                  key for the RC4 algorithm.
// pbHash:          Pointer to the hash.
// dwDataLen:       Length, in bytes, of the hash.
// Data1:           Password string used to create a symmetric key.
//                  information about the HMAC hash.
// 
	HCRYPTPROV  hProv{ 0 };
	HCRYPTHASH  hHash{ 0 };
	PBYTE       pbHash{ nullptr };
	DWORD dwDataLen{ 32 };

	wsHash.clear();
	DWORD dwResult{ 0 };
	do
	{
		//--------------------------------------------------------------------
		// Acquire a handle to the default RSA cryptographic service provider.
		if (!CryptAcquireContext(
			&hProv,                   // handle of the CSP
			NULL,                     // key container name
			NULL,                     // CSP name
			PROV_RSA_AES,            // provider type
			CRYPT_VERIFYCONTEXT))     // no key access is requested
		{
			dwResult = GetLastError();
			break;
		}

		//--------------------------------------------------------------------
		// Derive a symmetric key from a hash object by performing the
		// following steps:
		//    1. Call CryptCreateHash to retrieve a handle to a hash object.
		//    2. Call CryptHashData to add a text string (password) to the 
		//       hash object.
		//    3. Call CryptDeriveKey to create the symmetric key from the
		//       hashed password derived in step 2.
		// You will use the key later to create an HMAC hash object. 
		if (!CryptCreateHash(
			hProv,					// handle of the CSP
			algid,					// hash type
			0,						// hash key
			0,						// reserved
			&hHash))				// address of hash object handle
		{
			dwResult = GetLastError();
			break;
		}

		if (!CryptHashData(
			hHash,
			pContent,
			fbytes,
			0))
		{
			dwResult = GetLastError();
			break;
		}

		switch (algid)
		{
		case CALG_SHA1:
			dwDataLen = 20;
			break;
		case CALG_SHA_256:
			dwDataLen = 32;
			break;
		case CALG_SHA_512:
			dwDataLen = 64;
			break;
		case CALG_MD5:
			dwDataLen = 16;
			break;
		}
		pbHash = new BYTE[dwDataLen];

		if (!CryptGetHashParam(
			hHash,				// handle of the HMAC hash object
			HP_HASHVAL,			// query on the hash value
			pbHash,				// filled on second call
			&dwDataLen,			// length, in bytes, of the hash
			0))
		{
			dwResult = GetLastError();
			break;
		}

		wstringstream ss;
		for (unsigned i = 0; i < dwDataLen; ++i)
			ss << uppercase << hex << setw(2) << setfill(L'0') << pbHash[i];
		wsHash = ss.str();
	} while (false);

	// Free resources.
	if (hHash)
		CryptDestroyHash(hHash);
	if (hProv)
		CryptReleaseContext(hProv, 0);
	if (pbHash)
		delete[] pbHash;
	if (pContent)
		delete[] pContent;

	return 0;
}