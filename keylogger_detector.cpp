#include <winsock2.h> // network
#include <ws2tcpip.h> // network
#include <windows.h> // windows api
#include <tlhelp32.h> // take snapshots if the running processes
#include <psapi.h> // get detailed information about running processes
#include <iostream> // i/o stream operations 
#include <string> // string operations
#include <vector> // used later for detection results
#include <fstream> // file stream operations 
#include <iomanip>  // formatting our console output nicely
#include <ctime> // time operations
#include <algorithm> // for transform to use when comparing process names and file paths
#include <cstdlib> // standard library utilities
#include <conio.h> // console i/o
#include <iphlpapi.h> // netowkr monitoring

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ------------------------------
// data structures
// ------------------------------

struct DetectionResult {
    std::string method; // tell us how we detected the keylogger
    std::string details; // the actual information about what we found
    std::string severity; // how serious is this detection?
};

std::vector<DetectionResult> detections; // stores all detection results

// ------------------------------
// helper functions
// ------------------------------
std::string GetFormattedTime() {

    time_t now = time(0);
    struct tm timeinfo;
    
    localtime_s(&timeinfo, &now);
    
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    
    return std::string(buffer);
}

bool FileExists(const std::string& filename) {
    std::ifstream file(filename);

    return file.good();   
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string(); // firstly, check if the wide string is empty

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);

    std::string strTo(size_needed, 0);

    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);

    return strTo;
}

// ------------------------------
// behavioral process scanning
// ------------------------------

void ScanRunningProcesses() {
    std::cout << "\n[SCANNING] Checking running processes for keylogger behavior...\n";
    std::cout << "----------------------------------------\n";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot = INVALID_HANDLE_VALUE) {
        std::cout << "ERROR: Could not create process snapshot\n";
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    std::vector<std::string> suspiciousNames = {
        "keylogger",
        "keylog",
        "kl",
        "logger",
        "keycapture",
        "keystroke",
        "keymonitor"
    };

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::string processName = WStringToString(pe32.szExeFile);

            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            // check 1
            for (const auto& suspicious : suspiciousNames) {
                if (processName.find(suspicious) != std::string::npos) {
                    DetectionResult result;
                    result.method = "Process Name Detection";
                    result.details = "Found suspicious process: " + WStringToString(pe32.szExeFile) + 
                                   " (PID: " + std::to_string(pe32.th32ProcessID) + ")";
                    result.severity = "HIGH";
                    detections.push_back(result);
                    
                    std::cout << "[ALERT] " << result.details << "\n";
                }
            }

            // check 2
            if (processName == "python.exe" || processName == "pythonw.exe") {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                if (hProcess != NULL) {
                    HMODULE hMods[1024];
                    DWORD cbNeeded;
                    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                        wchar_t szModName[MAX_PATH];
                        bool hasKeyboardLib = false;

                        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                                std::wstring wModName(szModName);
                                std::string modName = WStringToString(wModName);

                                std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);

                                if (modName.find("pynput") != std::string::npos ||
                                    modName.find("keyboard") != std::string::npos ||
                                    modName.find("pyhook") != std::string::npos) {
                                    hasKeyboardLib = true;
                                    break;
                                }
                            }
                        }

                        if (hasKeyboardLib) {
                            DetectionResult result;
                            result.method = "Python Keylogger Detection";
                            result.details = "Python process (PID: " + std::to_string(pe32.th32ProcessID) + ") is using the keyboard monitoring library (pynput/keyboard)";
                            result.severity = "HIGH";
                            detections.push_back(result);

                            std::cout << "[ALERT] " << result.details << "\n";
                        }
                    }
                    CloseHandle(hProcess);
                }
            }

        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

// ------------------------------
// keyboard hook detection
// ------------------------------

void DetectKeyboardHooks() {
    std::cout << "\n[SCANNING] Checking for processes using keyboard hooks...\n";
    std::cout << "----------------------------------------\n";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "ERROR: Could not create snapshot\n";
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID < 100) continue;
            if (pe32.th32ProcessID == GetCurrentProcessId()) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

            if (hProcess != NULL) {
                HMODULE hMods[1024];
                DWORD cbNeeded;
                bool hasUser32 = false;
                bool isSmallProcess = false;            
                
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    wchar_t szModName[MAX_PATH];
                    
                    int moduleCount = cbNeeded / sizeof(HMODULE);
                    if (moduleCount < 20) {
                        isSmallProcess = true;
                    }
                    
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                            std::wstring wModName(szModName);
                            std::string modName = WStringToString(wModName);
                            
                            std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
                            
                            if (modName.find("user32.dll") != std::string::npos) {
                                hasUser32 = true;
                            }
                        }
                    }
                }
                if (hasUser32 && isSmallProcess) {
                    std::string procName = WStringToString(pe32.szExeFile);
                    std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
                    
                    if (procName.find("explorer") == std::string::npos &&
                        procName.find("dwm") == std::string::npos &&
                        procName.find("winlogon") == std::string::npos) {
                        
                        DetectionResult result;
                        result.method = "Hook Detection (Behavioral)";
                        result.details = "Process " + WStringToString(pe32.szExeFile) + 
                                       " (PID: " + std::to_string(pe32.th32ProcessID) + 
                                       ") uses user32.dll and has few modules (possible keylogger)";
                        result.severity = "MEDIUM";
                        detections.push_back(result);
                        
                        std::cout << "[ALERT] " << result.details << "\n";
                    }
                }
                CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}



// ------------------------------
// log file detection
// ------------------------------

void DetectLogFiles() {
    std::cout << "\n[SCANNING] Checking for keylogger log files...\n";
    std::cout << "----------------------------------------\n";

    std::vector<std::string> logFiles = {
        "keylogger.txt",
        "keylog.txt",
        "pythonkeylog.txt",
        "keystrokes.txt",
        "keys.txt",
        "log.txt",
        "capture.txt",
        "monitor.txt"
    };

    std::vector<std::string> searchPaths = {
        ".",  
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Desktop",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\Documents",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\AppData\\Local",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\AppData\\Roaming"
    };

    for (const auto& path : searchPaths) {
        for (const auto& logFile : logFiles) {
            std::string fullPath = path + "\\" + logFile;
            if (path == ".") fullPath = logFile;
            
            if (FileExists(fullPath)) {
                WIN32_FIND_DATAA findData;
                HANDLE hFind = FindFirstFileA(fullPath.c_str(), &findData);
                
                if (hFind != INVALID_HANDLE_VALUE) {
                    FILETIME ftWrite = findData.ftLastWriteTime;
                    FILETIME ftNow;
                    SYSTEMTIME stUTC, stLocal;
                    GetSystemTimeAsFileTime(&ftNow);
                    
                    ULARGE_INTEGER ulWrite, ulNow;
                    ulWrite.LowPart = ftWrite.dwLowDateTime;
                    ulWrite.HighPart = ftWrite.dwHighDateTime;
                    ulNow.LowPart = ftNow.dwLowDateTime;
                    ulNow.HighPart = ftNow.dwHighDateTime;

                    ULONGLONG diffSeconds = (ulNow.QuadPart - ulWrite.QuadPart) / 10000000;
                    
                    DWORD fileSize = findData.nFileSizeLow;
                    
                    if (diffSeconds < 120 && fileSize > 0) {
                        DetectionResult result;
                        result.method = "Log File Detection (Behavioral)";
                        result.details = "Found actively modified log file: " + fullPath + 
                                       " (Size: " + std::to_string(fileSize) + 
                                       " bytes, Modified " + std::to_string(diffSeconds) + " seconds ago)";
                        result.severity = "HIGH";
                        detections.push_back(result);
                        
                        std::cout << "[ALERT] " << result.details << "\n";
                    } else if (FileExists(fullPath)) {
                        DetectionResult result;
                        result.method = "Log File Detection";
                        result.details = "Found suspicious log file: " + fullPath + 
                                       " (Size: " + std::to_string(fileSize) + " bytes)";
                        result.severity = "MEDIUM";
                        detections.push_back(result);
                        
                        std::cout << "[ALERT] " << result.details << "\n";
                    }
                    
                    FindClose(hFind);
                }
            }
        }
    }
}

// ------------------------------
// file system monitoring
// ------------------------------
void MonitorFileActivity() {
    std::cout << "\n[SCANNING] Monitoring file system activity...\n";
    std::cout << "----------------------------------------\n";
    
    std::vector<std::string> targetFiles = {
        "keylogger.txt",
        "keylog.txt",
        "pythonkeylog.txt",
        "keystrokes.txt",
        "keys.txt"
    };
    for (const auto& targetFile : targetFiles) {
        if (FileExists(targetFile)) {

            HANDLE hFile = CreateFileA(targetFile.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, NULL
            );
            
            if (hFile == INVALID_HANDLE_VALUE) {
                DWORD error = GetLastError();
                if (error == ERROR_SHARING_VIOLATION) {
                    DetectionResult result;
                    result.method = "File Activity Monitoring (Behavioral)";
                    result.details = targetFile + " is currently being written to by another process (keylogger active!)";
                    result.severity = "HIGH";
                    detections.push_back(result);
                    
                    std::cout << "[ALERT] " << result.details << "\n";
                }
            } else {
                CloseHandle(hFile);
            }
        }
    }
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("*.txt", &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string fileName = findData.cFileName;

            if (fileName == "README.txt" || fileName.find("readme") != std::string::npos) {
                continue;
            }

            FILETIME ftWrite = findData.ftLastWriteTime;
            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);

            ULARGE_INTEGER ulWrite, ulNow;
            ulWrite.LowPart = ftWrite.dwLowDateTime;
            ulWrite.HighPart = ftWrite.dwHighDateTime;
            ulNow.LowPart = ftNow.dwLowDateTime;
            ulNow.HighPart = ftNow.dwHighDateTime;
            
            ULONGLONG diffSeconds = (ulNow.QuadPart - ulWrite.QuadPart) / 10000000;
            DWORD fileSize = findData.nFileSizeLow;

            if (diffSeconds < 60 && fileSize > 0 && fileSize < 1000000) { 
                HANDLE hTestFile = CreateFileA(fileName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL
                );
                
                if (hTestFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION) {
                    DetectionResult result;
                    result.method = "File Activity Monitoring (Pattern Detection)";
                    result.details = "Suspicious file activity: " + fileName + " is being actively written to (possible keylogger log)";
                    result.severity = "MEDIUM";
                    detections.push_back(result);
                    
                    std::cout << "[ALERT] " << result.details << "\n";
                } else if (hTestFile != INVALID_HANDLE_VALUE) {
                    CloseHandle(hTestFile);
                }
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }
}

// ------------------------------
// network connection monitoring
// ------------------------------

void DetectNetworkConnections() {
    std::cout << "\n[SCANNING] Checking for suspicious network connections...\n";
    std::cout << "----------------------------------------\n";

    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    
    dwRetVal = GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
    
    if (pTcpTable == NULL) {
        std::cout << "ERROR: Could not allocate memory for TCP table\n";
        return;
    }

    dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (dwRetVal == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];
            DWORD processId = row.dwOwningPid;
            
            if (processId == GetCurrentProcessId()) {
                continue;
            }
            
            if (row.dwState == MIB_TCP_STATE_ESTAB) {
                unsigned char* localIpBytes = (unsigned char*)&row.dwLocalAddr;
                unsigned char* remoteIpBytes = (unsigned char*)&row.dwRemoteAddr;
                
                char localIp[16], remoteIp[16];
                sprintf_s(localIp, sizeof(localIp), "%d.%d.%d.%d",
                    localIpBytes[0], localIpBytes[1], localIpBytes[2], localIpBytes[3]);
                sprintf_s(remoteIp, sizeof(remoteIp), "%d.%d.%d.%d",
                    remoteIpBytes[0], remoteIpBytes[1], remoteIpBytes[2], remoteIpBytes[3]);
                
                bool isExternalConnection = (strcmp(remoteIp, "127.0.0.1") != 0 && strcmp(remoteIp, "0.0.0.0") != 0);
                
                unsigned short remotePort = ntohs((unsigned short)row.dwRemotePort);
                bool isUnusualPort = (remotePort != 80 && remotePort != 443 && remotePort != 53 && remotePort != 25 && 
                                     remotePort != 587 && remotePort != 465);
                
                if (isExternalConnection) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                    if (hProcess != NULL) {
                        wchar_t processName[MAX_PATH];
                        DWORD processNameSize = MAX_PATH;
                        
                        if (QueryFullProcessImageNameW(hProcess, 0, processName, &processNameSize)) {
                            std::string procName = WStringToString(processName);
                            
                            size_t lastSlash = procName.find_last_of("\\/");
                            if (lastSlash != std::string::npos) {
                                procName = procName.substr(lastSlash + 1);
                            }
                            
                            std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
                            
                            bool isPython = (procName == "python.exe" || procName == "pythonw.exe");
                            bool hasSuspiciousName = (procName.find("keylog") != std::string::npos ||
                                                     procName.find("logger") != std::string::npos ||
                                                     procName.find("capture") != std::string::npos);
                            
                            if (isPython || hasSuspiciousName || isUnusualPort) {
                                DetectionResult result;
                                result.method = "Network Connection Detection";
                                result.details = "Process " + procName + " (PID: " + std::to_string(processId) + 
                                               ") has outbound connection to " + std::string(remoteIp) + ":" + 
                                               std::to_string(remotePort) + " (possible data exfiltration)";
                                result.severity = (hasSuspiciousName || isPython) ? "HIGH" : "MEDIUM";
                                detections.push_back(result);
                                
                                std::cout << "[ALERT] " << result.details << "\n";
                            }
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        }
    } else {
        std::cout << "ERROR: Could not retrieve TCP table (Error: " << dwRetVal << ")\n";
    }
    
    if (pTcpTable != NULL) {
        free(pTcpTable);
    }
    
    PMIB_UDPTABLE_OWNER_PID pUdpTable = NULL;
    dwSize = 0;
    
    dwRetVal = GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
        
        if (pUdpTable != NULL) {
            dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            free(pUdpTable);
        }
    }
}

// ------------------------------
// reporting and summary
// ------------------------------

void GenerateReport() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "     DETECTION SUMMARY REPORT\n";
    std::cout << "========================================\n";
    std::cout << "Scan Time: " << GetFormattedTime() << "\n";
    std::cout << "Total Detections: " << detections.size() << "\n\n";
    
    if (detections.empty()) {
        std::cout << "[RESULT] No keyloggers detected.\n";
        std::cout << "This doesn't guarantee the system is clean - some keyloggers\n";
        std::cout << "use advanced techniques to avoid detection.\n";
    } else {
        std::cout << "DETECTIONS FOUND:\n";
        std::cout << "-----------------\n";
        
        int highCount = 0, mediumCount = 0;
        
        for (size_t i = 0; i < detections.size(); i++) {
            std::cout << "\n[" << (i + 1) << "] " << detections[i].method << "\n";
            std::cout << "    Severity: " << detections[i].severity << "\n";
            std::cout << "    Details: " << detections[i].details << "\n";
            
            if (detections[i].severity == "HIGH") highCount++;
            else if (detections[i].severity == "MEDIUM") mediumCount++;
        }
        
        std::cout << "\n";
        std::cout << "Severity Breakdown:\n";
        std::cout << "  HIGH: " << highCount << "\n";
        std::cout << "  MEDIUM: " << mediumCount << "\n";
    }
    
    std::cout << "\n========================================\n";
}

// ------------------------------
// main function
// ------------------------------

int main() {
    std::cout << "========================================\n";
    std::cout << "           KEYLOGGER DETECTOR           \n";
    std::cout << "========================================\n";
    std::cout << "\n";
    std::cout << "\n";
    std::cout << "Detection techniques:\n";
    std::cout << "  1. Behavioral process scanning (Python, C++, etc.)\n";
    std::cout << "  2. Keyboard hook detection (Windows API hooks)\n";
    std::cout << "  3. Log file pattern detection (actively written files)\n";
    std::cout << "  4. Real-time file activity monitoring\n";
    std::cout << "  5. Network connection monitoring (C2 server data exfiltration)\n";
    std::cout << "\n";
    std::cout << "CONTINUOUS MONITORING MODE\n";
    std::cout << "The detector will scan every 30 seconds.\n";
    std::cout << "Press 'q' and Enter to stop monitoring.\n";
    std::cout << "\n";
    std::cout << "Starting continuous monitoring...\n\n";
    
    bool monitoring = true;
    int scanCount = 0;

    while (monitoring) {
        scanCount++;
        std::cout << "\n";
        std::cout << "========================================\n";
        std::cout << "  SCAN #" << scanCount << " - " << GetFormattedTime() << "\n";
        std::cout << "========================================\n";

        detections.clear();

        ScanRunningProcesses();
        DetectKeyboardHooks();
        DetectLogFiles();
        MonitorFileActivity();
        DetectNetworkConnections();

        if (!detections.empty()) {
            GenerateReport();
        } else {
            std::cout << "\n[RESULT] No keyloggers detected in this scan.\n";
        }

        std::cout << "\nNext scan in 30 seconds... (Press 'q' + Enter to stop)\n";

        for (int i = 0; i < 30; i++) {
            Sleep(1000);
            if (_kbhit()) {
                char ch = _getch();
                if (ch == 'q' || ch == 'Q') {
                    while (_kbhit()) _getch();
                    monitoring = false;
                    break;
                }
            }
        }
    }

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  MONITORING STOPPED\n";
    std::cout << "========================================\n";
    std::cout << "Total scans performed: " << scanCount << "\n";
    std::cout << "Thank you for using the keylogger detector!\n";
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    
    return 0;
}
