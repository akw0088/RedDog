#include <windows.h>
#include <stdio.h>

class RedirectProcessIO
{
public:
	RedirectProcessIO();
	int start(char *child);
	void write(char *cmd);
	void close();
	void read(char *buffer, int length);


private:
	int CreateChildProcess();

	unsigned int process_pid;
	char szCmdline[1024];
	HANDLE handle_stdin_read;
	HANDLE handle_stdin_write;
	HANDLE handle_stdout_read;
	HANDLE handle_stdout_write;
};