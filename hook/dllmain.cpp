#include <windows.h>
#include <stdio.h>
#include <inttypes.h>
//detours
#include "../detours-master/include/detours.h"

#pragma comment (lib, "../detours-master/lib.X64/detours.lib")
#pragma warning(disable: 4996)

FILE* log_file = NULL;

BOOL(WINAPI* TrueWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten) = WriteProcessMemory;

__declspec(dllexport) BOOL WINAPI MyWriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten)
{
    auto r = TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    static SYSTEMTIME sm;
    GetSystemTime(&sm);

    printf("%d.%d.%d %d:%d:%d:%d MyWriteProcessMemory()\n"
        , sm.wYear
        , sm.wMonth
        , sm.wDay
        , sm.wHour
        , sm.wMinute
        , sm.wSecond
        , sm.wMilliseconds);

    if (log_file != NULL) {
        fprintf(log_file, "%d.%d.%d %d:%d:%d:%d  MyWriteProcessMemory()\n"
            , sm.wYear
            , sm.wMonth
            , sm.wDay
            , sm.wHour
            , sm.wMinute
            , sm.wSecond
            , sm.wMilliseconds);
    };

    return r;
};

void process_attach()
{
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    printf("process_attach()\n");

    log_file = fopen("D:\\hook.log", "wt");
    if (log_file != NULL) fprintf(log_file, "process_attach()\n");

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueWriteProcessMemory, MyWriteProcessMemory);
    DetourTransactionCommit();
};

void thread_attach()
{
    printf("thread_attach()\n");
    if (log_file != NULL) fprintf(log_file, "thread_attach()\n");
};

void thread_detach()
{
    printf("thread_detach()\n");
    if (log_file != NULL) fprintf(log_file, "thread_detach()\n");
};

void process_detach()
{
    printf("process_detach()\n");
    if (log_file != NULL) fprintf(log_file, "process_detach()\n");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueWriteProcessMemory, MyWriteProcessMemory);
    DetourTransactionCommit();

    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }

    FreeConsole();
};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: process_attach(); break;
    case DLL_THREAD_ATTACH:  thread_attach();  break;
    case DLL_THREAD_DETACH:  thread_detach();  break;
    case DLL_PROCESS_DETACH: process_detach(); break;
    }
    return TRUE;
};
