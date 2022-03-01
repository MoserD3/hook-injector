#include <windows.h>
#include <stdio.h>
#include <direct.h>
#include <tlhelp32.h>

#pragma warning(disable: 6387)

int get_process_id(const char* process_name = "TurboHUD.exe")
{
    while (true) {
        PROCESSENTRY32 pe32;
        HANDLE h_snapshot = NULL;

        pe32.dwSize = sizeof(PROCESSENTRY32);
        h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(h_snapshot, &pe32)) {
            do {
                if (strcmp(pe32.szExeFile, process_name) == 0)
                    return pe32.th32ProcessID;
            } while (Process32Next(h_snapshot, &pe32));
        };
        printf("get_process_id(%s) error!!\n", process_name);
        Sleep(500);
    };

    return NULL;
};

int inject_dll(const unsigned int& pid, const char* dll_name = "D:\\my.dll")
{
    if (pid == NULL)
        return 1;

    printf("Opening process %d...\n", pid);
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (h_process == NULL) {
        printf("Can`t open process %d!!\n", pid);
        return 2;
    };

    printf("Allocating memory in process %d...\n", pid);
    size_t dll_name_size = strlen(dll_name) + 1;
    LPVOID dll_memory_alloc = VirtualAllocEx(h_process, NULL, dll_name_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (dll_memory_alloc == NULL) {
        printf("Can`t allocate memory in process %d!!\n", pid);
        return 2;
    };

    printf("Write into process %d memory...\n", pid);
    if (!WriteProcessMemory(h_process, dll_memory_alloc, dll_name, dll_name_size, 0)) {
        printf("Can`t write into process %d memory...\n", pid);
        return 3;
    };

    DWORD dword;
    LPTHREAD_START_ROUTINE addr_load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA"));
    HANDLE dll_thread = CreateRemoteThread(h_process, NULL, 0, addr_load_library, dll_memory_alloc, 0, &dword);
    if (dll_thread == NULL) {
        printf("Fail to create remote thread...\n");
        return 4;
    };

    printf("%s successfully injected\n", dll_name);
    return 0;
};

int main(int argc, char** argv)
{
    char dll_full_name[200] = { 0 };
    auto r = _getcwd(dll_full_name, 100);
    sprintf_s(dll_full_name, "%s\\%s", dll_full_name, "hook.dll");
    inject_dll(get_process_id(), dll_full_name);
    return 0;
};
