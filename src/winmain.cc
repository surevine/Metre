/***

Copyright 2013-2016 Dave Cridland
Copyright 2014-2016 Surevine Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***/

#include <string>
#include <config.h>
#include <iostream>
#include <string.h>
#include <log.h>
#include <signal.h>
#include <fstream>
#include <router.h>
#include <windows.h>
#include <tchar.h>

namespace {
    class BootConfig {
    public:
        std::string config_file;
        std::string boot_method;

        BootConfig(int argc, char *argv[])
                : config_file("C:\\Metre\\metre.conf.xml"), boot_method() {
            if (argc < 1) return;
            for (int i = 1; i < argc; ++i) {
                char opt;
                switch (argv[i][0]) {
                    case '-':
                    case '/':
                        opt = argv[i][1];
                        break;
                    default:
                        //std::cerr << "Don't understand commandline arg " << argv[i] << std::endl;
                        exit(2);
                }
                ++i;
                if (!argv[i]) {
                    //std::cerr << "Missing argument for option '" << opt << "'" << std::endl;
                    exit(2);
                }
                switch (opt) {
                    case 'c':
                        config_file = argv[i];
                        break;
                    case 'd':
                        boot_method = argv[i];
                        break;
                }
            }
        }
    };

    std::unique_ptr<BootConfig> bc;
    std::unique_ptr<Metre::Config> config;

    void hup_handler(int s) {
        //config.reset(new Metre::Config(bc->config_file));
        //Metre::Router::reload();
        METRE_LOG(Metre::Log::INFO, "NOT Reloading config.");
    }

    void term_handler(int s) {
        METRE_LOG(Metre::Log::INFO, "Shutdown received.");
        Metre::Router::quit();
    }
}

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);

VOID WINAPI ServiceCtrlHandler(DWORD);

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME  "Metre"

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    DWORD Status = E_FAIL;

    bc = std::make_unique<BootConfig>(argc, argv);

    config = std::make_unique<Metre::Config>(bc->config_file, "C:\\Metre\\temp.log");

    if (bc->boot_method.empty()) {
        bc->boot_method = config->boot_method();
    }

    if (bc->boot_method != "service") {
        OutputDebugString(_T("Metre: ServiceMain: Wrong boot method"));
        goto EXIT;
    }
    config->log_init();
    config->logger().info("Service start");

    // Register our service control handler with the SCM
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) {
        goto EXIT;
    }

    // Tell the service controller we are starting
    ZeroMemory (&g_ServiceStatus,
                sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        OutputDebugString(_T("Metre: ServiceMain: SetServiceStatus returned error"));
    }

    /*
     * Perform tasks necessary to start the service here
     */

    // Create a service stop event to wait on later
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        // Error creating event
        // Tell service controller we are stopped and exit
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
            OutputDebugString(_T("Metre: ServiceMain: SetServiceStatus returned error"));
        }
        goto EXIT;
    }

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        OutputDebugString(_T("Metre: ServiceMain: SetServiceStatus returned error"));
    }

    // Start a thread that will perform the main task of the service
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

    // Wait until our worker thread exits signaling that the service needs to stop
    WaitForSingleObject(hThread, INFINITE);

    /*
     * Perform any cleanup tasks
     */

    CloseHandle(g_ServiceStopEvent);

    // Tell the service controller we are stopped
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        OutputDebugString(_T("Metre: ServiceMain: SetServiceStatus returned error"));
    }

EXIT:
    return;
}

int main(int argc, char *argv[]) {
    try {
        // Parse arguments.
        bc = std::make_unique<BootConfig>(argc, argv);
        if (bc->boot_method.empty() || bc->boot_method == "service") {
            SERVICE_TABLE_ENTRY ServiceTable[] = {
                    {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
                    {NULL, NULL}
            };
            if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
                return GetLastError();
            }
            return 0;
        }
    } catch (std::runtime_error &e) {
        std::cout << "Error while loading config: " << e.what() << std::endl;
        return 1;
    }
    try {
        // Load config, first pass.
        config = std::make_unique<Metre::Config>(bc->config_file, "C:\\Metre\\temp.log");
        config->log_init();
        if (bc->boot_method.empty()) {
            bc->boot_method = config->boot_method();
        }
        config->logger().info("Win32 startup, boot_method {}", bc->boot_method);
        if (bc->boot_method == "none") {
            config->log_init();
            config->write_runtime_config();
            Metre::Router::main([](){
                return false;
            });
        } else {
            std::cerr << "I don't know what " << bc->boot_method << " means." << std::endl;
            return 1;
        }
    } catch (std::runtime_error &e) {
        std::cout << "Error while loading config: " << e.what() << std::endl;
        return 2;
    }
    config.reset(nullptr);
    bc.reset(nullptr);
    return 0;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP :
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        /*
         * Perform tasks necessary to stop the service here
         */

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
            OutputDebugString(_T("Metre: ServiceCtrlHandler: SetServiceStatus returned error"));
        }

        // This will signal the worker thread to start shutting down
        SetEvent(g_ServiceStopEvent);

        break;

    default:
        break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    config->write_runtime_config();

    Metre::Router::main([]() {
        return (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_OBJECT_0);
    });

    return ERROR_SUCCESS;
}
