#ifndef CRYPTO_H_INCLUDED
#define CRYPTO_H_INCLUDED

class CMyCrypto {

public:
    CMyCrypto(LPTSTR lpPassword, ALG_ID algorithm);
    ~CMyCrypto();

    BOOL Encrypt(LPBYTE pData, LPDWORD pdwDataSize,
                 DWORD dwBufferSize, BOOL bFinal);
    BOOL Decrypt(LPBYTE pData, LPDWORD dwDataSize,
                 BOOL bFinal);

private:
    HCRYPTPROV m_hProv;
    HCRYPTKEY  m_hKey;
};


#endif