#define UNICODE
#define _UNICODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include "Utils.h"

BOOL FindModule(LPMODULEENTRY32W pMe, LPVOID moduleName)
{
    printf("Module path: %s\n", utf16toutf8(pMe->szExePath, utf8_buffer, M_BUF_SIZ));
    WCHAR moduleNameUpr[2048], tmpModulePathUpr[2048];
    wcscpy(moduleNameUpr, moduleName);
    wcsupr(moduleNameUpr);
    wcscpy(tmpModulePathUpr, pMe->szExePath);
    wcsupr(tmpModulePathUpr);
    if (wcsstr(tmpModulePathUpr, moduleNameUpr))
    {
        printf("Found it!\n");
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char const *argv[])
{
    EnumModules(GetProcessIdByName(TEXT("notepad.exe")), FindModule, TEXT("dlltest.dll"));
    return 0;
}
