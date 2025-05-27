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
    UNICODE_INIT();

    char processName[MAX_PATH] = {0}, dllPath[MAX_PATH] = {0};
    WCHAR processNameW[MAX_PATH], dllPathW[MAX_PATH];

    if (argc >= 2) 
    { strcpy(processName, argv[1]); }
    if (argc >= 3)
    { strcpy(dllPath, argv[2]); }

    if (processName[0] == '\0')
    {
        printf("Process name: ");
        scanf("%s", processName);
    }
    if (dllPath[0] == '\0')
    {
        printf("Dll path: ");
        scanf("%s", dllPath);
    }

    utf8toutf16(processName, processNameW, MAX_PATH);
    utf8toutf16(dllPath, dllPathW, MAX_PATH);
    EnumModules(GetProcessIdByName(processNameW), FindModule, dllPathW);
    return 0;
}
