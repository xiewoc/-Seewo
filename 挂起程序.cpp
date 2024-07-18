#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>

//提升权限为DEBUG,处理GetLastError返回5 无权限操作错误
BOOL EnableDebugPrivilege(){
    HANDLE hToken;
    BOOL fOk=FALSE;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)){
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount=1;
        LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);

        tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);

        fOk=(GetLastError()==ERROR_SUCCESS);
        CloseHandle(hToken);
    }
    return fOk;
}

// 获取进程句柄
HANDLE get_process_handle(DWORD process_id) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed for PID " << process_id << ": " << GetLastError() << std::endl;
    }
    return hProcess;
}

// 挂起进程中的所有线程
void suspend_threads(HANDLE hProcess) {
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        if (Thread32First(hThreadSnap, &te)) {
            do {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
                    if (te.th32OwnerProcessID == GetProcessId(hProcess)) {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (hThread != NULL) {
                            SuspendThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                }
            } while (Thread32Next(hThreadSnap, &te));
        }
    }
    CloseHandle(hThreadSnap);
}

int main() {
	BOOL EnableDebugPrivilege();
	EnableDebugPrivilege();
    std::vector<std::string> exeNames = {"SeewoAbility.exe", "SeewoFreezeUpdateAssist.exe", "SeewoCore.exe", "SeewoServiceAssistant.exe", "SeewoIwbAssistant.exe"};
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed for processes: " << GetLastError() << std::endl;
        return 1;
    }

    if (!Process32First(hSnapshot, &pe)) {
        std::cerr << "Process32First failed: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return 1;
    }

    do {
        std::string processName(pe.szExeFile);
        for (const auto& name : exeNames) {
            if (processName == name) {
                HANDLE hProcess = get_process_handle(pe.th32ProcessID);
                if (hProcess != NULL) {
                    suspend_threads(hProcess);
                    CloseHandle(hProcess);
                }
                break;
            }
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    std::cout << "All specified programs have been attempted to be suspended." << std::endl;

    return 0;
}
