#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif

#include <windows.h>
#include <wincrypt.h>
#include "crypto.h"
#include <stdio.h>
#include <string>

using namespace std;

CMyCrypto::CMyCrypto(LPTSTR pszPassword, ALG_ID algorithm)
{
    m_hProv = NULL;
    m_hKey  = NULL;

    if (!CryptAcquireContext(&m_hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL,
        CRYPT_MACHINE_KEYSET)) {

        if (!CryptAcquireContext(&m_hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL,
            CRYPT_MACHINE_KEYSET|CRYPT_NEWKEYSET)) {

                    printf("last error is: %x", GetLastError());
        }
    }

    HCRYPTHASH hHash;

    if (CryptCreateHash(m_hProv,
                        CALG_MD5,
                        0,
                        0,
                        &hHash)) { 

        if (CryptHashData(hHash,
                          (LPBYTE)pszPassword, 
                          lstrlen(pszPassword)*sizeof(TCHAR),
                          0)) {

            CryptDeriveKey(m_hProv,
                           algorithm,
                           hHash,
                           CRYPT_EXPORTABLE | 0x00280000,
                           &m_hKey);
        }
        CryptDestroyHash(hHash);
    }
}

CMyCrypto::~CMyCrypto()
{
    if (m_hKey != NULL) {
        CryptDestroyKey(m_hKey);
    }

    if (m_hProv != NULL) {
        CryptReleaseContext(m_hProv, 0);
    }
}

BOOL CMyCrypto::Encrypt(LPBYTE pData, LPDWORD pdwDataSize,
                        DWORD dwBufferSize, BOOL bFinal){

   bool b = CryptEncrypt(m_hKey,
                        0,
                        bFinal,
                        0,
                        pData,
                        pdwDataSize,
                        dwBufferSize);

                        return b;
}

BOOL CMyCrypto::Decrypt(LPBYTE pData, LPDWORD pdwDataSize,
                        BOOL bFinal){

    return CryptDecrypt(m_hKey,
                        0,
                        bFinal,
                        0,
                        pData,
                        pdwDataSize);
}