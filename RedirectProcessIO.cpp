#include "RedirectProcessIO.h"


RedirectProcessIO::RedirectProcessIO()
{
	handle_stdin_read = NULL;
	handle_stdin_write = NULL;
	handle_stdout_read = NULL;
	handle_stdout_write = NULL;

	memset(szCmdline, 0, 1024);
}

int RedirectProcessIO::start(char *child)
{
	SECURITY_ATTRIBUTES saAttr;

	strncpy(szCmdline, child, 1023);


	// Set the bInheritHandle flag so pipe handles are inherited. 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for the child process's STDOUT. 
	if (!CreatePipe(&handle_stdout_read, &handle_stdout_write, &saAttr, 0))
	{
		printf("CreatePipe Failed\n");
		return -1;
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(handle_stdout_read, HANDLE_FLAG_INHERIT, 0))
	{
		printf("SetHandleInformation Failed\n");
		return -1;
	}

	// Create a pipe for the child process's STDIN. 
	if (!CreatePipe(&handle_stdin_read, &handle_stdin_write, &saAttr, 0))
	{
		printf("CreatePipe Failed\n");
		return -1;
	}

	// Ensure the write handle to the pipe for STDIN is not inherited. 
	if (!SetHandleInformation(handle_stdin_write, HANDLE_FLAG_INHERIT, 0))
	{
		printf("SetHandleInformation Failed\n");
		return -1;
	}

	int ret = CreateChildProcess();

	// Create the child process. 
	return	ret;
}



int RedirectProcessIO::CreateChildProcess()
{
	// Create a child process that uses the previously created pipes for STDIN and STDOUT.
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = handle_stdout_write;
	siStartInfo.hStdOutput = handle_stdout_write;
	siStartInfo.hStdInput = handle_stdin_read;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Create the child process. 

	bSuccess = CreateProcess(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

	if (!bSuccess)
	{
		printf("CreateProcess failed\n");
		return -1;
	}

	// Close handles to the child process and its primary thread.
	// Some applications might keep these handles to monitor the status
	// of the child process, for example. 

	process_pid = piProcInfo.dwProcessId;

	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);

	// Close handles to the stdin and stdout pipes no longer needed by the child process.
	// If they are not explicitly closed, there is no way to recognize that the child process has ended.
	CloseHandle(handle_stdout_write);
	CloseHandle(handle_stdin_read);

	return 0;
}




int RedirectProcessIO::write(char *cmd)
{
	// Read from a file and write its contents to the pipe for the child's STDIN.
	// Stop when there is no more data. 
	DWORD dwWritten;
	BOOL bSuccess = FALSE;

	bSuccess = WriteFile(handle_stdin_write, cmd, strlen(cmd), &dwWritten, NULL);
	if (bSuccess == 0)
	{
		printf("WriteFile to pipe failed error code %d\n", GetLastError());
		return -1;
	}


	return 0;

}

int RedirectProcessIO::close()
{
	if (!CloseHandle(handle_stdin_write))
	{
		printf("CloseHandle failed\n");
		return -1;
	}

	return 0;
}

int RedirectProcessIO::read(char *buffer, int length)
{
	DWORD bytesRead = 0;
	DWORD bytesAvail = 0;
	DWORD bytesLeft = 0;
	BOOL bSuccess = FALSE;

	// Non blocking check to see if pipe has data
	bSuccess = PeekNamedPipe(handle_stdout_read, buffer, length, &bytesRead, &bytesAvail, &bytesLeft);
	if (bSuccess == 0)
	{
		printf("PeekNamedPipe failed\n");
		return -1;
	}

	// now actually remove that data from the pipe (blocking if empty)
	if (bytesRead)
	{
		int length = bytesRead;
		bSuccess = ReadFile(handle_stdout_read, buffer, length, &bytesRead, NULL);
		if (bSuccess == 0)
		{
			printf("ReadFile from pipe failed\n");
			return -1;
		}
	}

	return 0;
}

