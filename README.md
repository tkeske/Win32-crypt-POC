# Win32 crypter

Written in C++ and utilizes Wincrypt API.
Control server backend is written in PHP.

Crypter communicates with backend hidden service in tor network
with the help of cURL http requests in order to obtain crypt/decrypt password for given machine.

This sample is meant to be downloaded via launcher which source code is also provided.

Compile with these flags:

-static-libgcc -static-libstdc++ -s -Os

Build dependencies:

-all the .a curl libraries from curl_devel/lib 
-libws2_32.a
-libwldap32.a
-libwinmm.a
-libgdi32.a
-libadvapi32.a
-libshlwapi.a
-libwininet.a

It is meant to be statically linked standalone executable.