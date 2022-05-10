#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winbase.h>
#include <wchar.h>

#define BUFFER_SIZE MAX_PATH
#define MAX_LINE 80

char *read_command_line(void);
char **parse_command(char *line);
int shell_excute(char **args);
int shell_exit(char **args);
int shell_print_processes_info(char **args);
int kill_process_by_name(char **args);
int suspend_by_name(char **args);
int resume_by_name(char **args);
void suspend(DWORD processId);
void resume(DWORD processId);
int shell_help(char **args);
void shell_working(char **args);
int shell_time(char **args);
int shell_date(char **args);
int get_current_directory(char **args);
int set_current_directory(char **args);
int list_files(char **args);
int env(char **args);
int addenv(char **args);
int path(char **args);
int addpath(char **args);


HANDLE hJob;
JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
PROCESS_INFORMATION pi   = {0};
STARTUPINFO si   = {0};

/*
  List of builtin commands, followed by their corresponding functions.
*/
char *builtin_str[] = {
    "help",
    "kill",
    "exec",
    "list",
    "exit",
    "pause",
    "resume",
    "time",
    "date",
    "getcwd",
    "setcwd",
    "dir",
    "env",
    "addenv",
    "path",
    "addpath"
};

int (*builtin_func[]) (char **args) = {
    &shell_help,
    &kill_process_by_name,
    &shell_excute,
    &shell_print_processes_info,
    &shell_exit,
    &suspend_by_name,
    &resume_by_name,
    &shell_time,
    &shell_date,
    &get_current_directory,
    &set_current_directory,
    &list_files,
    &env,
    &addenv,
    &path,
    &addpath
};


int main(void) {
    
    hJob = CreateJobObject(NULL, NULL);
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
	char **args; /* command line arguments */
	int status = 1; /* flag to determine when to exit program */
	char *line;
	
    printf("\t\tWELCOME TO MY SHELL\n\n");
	do {
		printf("myShell>");
		fflush(stdin);
		line = read_command_line();
		args = parse_command(line);
        shell_working(args);
		free(line);
		free(args);
	} while(status);
	return 0;
}




char *read_command_line(void){
	char *line = malloc(sizeof(char) * MAX_LINE);
	gets(line);
	return line;
}

char **parse_command(char *line){
	int position = 0;
	int size = MAX_LINE/2 + 1;
	char *arg;
	char **args = malloc(size * sizeof(char*));
	arg = strtok(line, " \n\t");
	
	while(arg != NULL){
		args[position] = arg;
		position++;
		arg = strtok(NULL, " \n\t");
	}
	args[position] = NULL;
	return args;
}

int shell_excute(char **args){
	
	si.cb = sizeof(si);
	
	if (args[2] && strcmp(args[2], "&") != 0){
		fprintf(stderr, "Bad command or filename ....\n\n");
		return -1;
	}

	if (!CreateProcess(NULL, 
		args[1], 
		NULL, 
		NULL, 
		FALSE, 
		CREATE_NEW_CONSOLE | CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | CREATE_UNICODE_ENVIRONMENT, 
		NULL, 
		NULL, 
		&si,
		&pi))
	{
		fprintf(stderr, "Bad command or filename ....\n");
		return -1;
	}
	else{
        AssignProcessToJobObject(hJob, pi.hProcess);
        ResumeThread(pi.hThread);
		if (!args[2]){
			WaitForSingleObject(pi.hProcess, INFINITE);
			printf("\nChild Complete\n\n");
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return 0;
		}
		else if (strcmp(args[2], "&") != 0){
			fprintf(stderr, "Bad command or filename ....\n\n");
			return -1;
		}
		else{
			return 0;
		}
	}	
}

int shell_print_processes_info(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
	printf("--------PROCESS LISTING--------\n");
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 ProcessInfo = {0};
    ProcessInfo.dwSize = sizeof(PROCESSENTRY32);
    int count = 0;


    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapShot)
    {
        printf("Error...\n");
        return -1;
    }
    printf("Create tool success...\n");
   
    while (Process32Next(hSnapShot, &ProcessInfo)){
        if ( ProcessInfo.th32ParentProcessID == GetCurrentProcessId() || ProcessInfo.th32ProcessID == GetCurrentProcessId() )
        {
        _tprintf(TEXT("\n\n====================================================="));
        _tprintf(TEXT("\n\tPROCESS NO:          %d"), ++count);
        _tprintf(TEXT("\n\tNO. OF THREAD:       %d"), ProcessInfo.cntThreads);
        _tprintf(TEXT("\n\tSIZE:                %d"), ProcessInfo.dwSize);
        _tprintf(TEXT("\n\tBASE PRIORITY:       %d"), ProcessInfo.pcPriClassBase);
        _tprintf(TEXT("\n\tPROCESS NAME:        %s"), ProcessInfo.szExeFile);
        _tprintf(TEXT("\n\tPARENT PROCESS ID:   %d"), ProcessInfo.th32ParentProcessID);
        _tprintf(TEXT("\n\tPROCESS ID:          %d"), ProcessInfo.th32ProcessID);
        }
    }
    printf("\n\n");
    CloseHandle(hSnapShot);
    return 0;
}

int kill_process_by_name(char **args)
{   
    char *filename = args[1];
    if (args[2]){
        printf("\nBad filename....\n\n");
        return 0;
    }
    int check_name = 0;
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (strcmp(pEntry.szExeFile, filename) == 0)
        {   check_name = 1;
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD) pEntry.th32ProcessID);
            if (hProcess != NULL)
            {   
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    if (check_name == 0){
        printf("\nBad filename....\n\n");
    }
    CloseHandle(hSnapShot);
    return 0;
}

int suspend_by_name(char **args)
{   
    char *filename = args[1];
    int check_name = 0;
    if (args[2]){
        printf("\nBad command or filename....\n\n");
        return 0;
    }
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (strcmp(pEntry.szExeFile, filename) == 0)
        {   check_name = 1;
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (DWORD) pEntry.th32ProcessID);
            if (hProcess != NULL)
            {

                suspend((DWORD) pEntry.th32ProcessID);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    if (check_name == 0){
        printf("\nBad file name....\n\n");
    }
    CloseHandle(hSnapShot);
    return 0;
}




void suspend(DWORD processId)
{
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 threadEntry; 
    threadEntry.dwSize = sizeof(THREADENTRY32);

    Thread32First(hThreadSnapshot, &threadEntry);

    do
    {
        if (threadEntry.th32OwnerProcessID == processId)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
                threadEntry.th32ThreadID);
            
            SuspendThread(hThread);
            CloseHandle(hThread);
        }
    } while (Thread32Next(hThreadSnapshot, &threadEntry));

    CloseHandle(hThreadSnapshot);
}


void resume(DWORD processId)
{
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 threadEntry; 
    threadEntry.dwSize = sizeof(THREADENTRY32);

    Thread32First(hThreadSnapshot, &threadEntry);

    do
    {
        if (threadEntry.th32OwnerProcessID == processId)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
                threadEntry.th32ThreadID);
            
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    } while (Thread32Next(hThreadSnapshot, &threadEntry));

    CloseHandle(hThreadSnapshot);
}


int resume_by_name(char **args)
{   char *filename = args[1];
    if (args[2]){
        printf("\nBad command or filename....\n\n");
        return 0;
    }
    int check_name = 0;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {   
        if (strcmp(pEntry.szExeFile, filename) == 0)
        {   check_name = 1;
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, (DWORD) pEntry.th32ProcessID);
            if (hProcess != NULL)
            {

                resume((DWORD) pEntry.th32ProcessID);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    if (check_name == 0){
        printf("\nBad file name....\n\n");
    }
    CloseHandle(hSnapShot);
    return 0;
}


int shell_help(char **args){
    if (!args[1])
    {
        printf("\n\n\tWELCOME TO MY SHELL\n");
        printf("\nmyShell supports the following commands:\n");
        printf("\nlist                              : List all background processes.");
        printf("\nhelp                              : Print this help.");
        printf("\nexit                              : Exit my shell and killing all child processes.");
        printf("\nkill   <process_name>             : Kill a running process.");
        printf("\nexec   <process_name>             : Run a running process, add & to run in background mode.");
        printf("\npause  <process name>             : Pause a process.");
        printf("\nresume <process name>             : Resume a process.");
        printf("\ntime                              : Get the local current time.");
        printf("\ndate                              : Get the local current date.");
        printf("\ngetcwd                            : Get the current working directory.");
        printf("\nsetcwd                            : Set the current working directory.");
        printf("\ndir                               : List all the files and directory in the working directory.");
        printf("\nenv                               : List all the environment system variables.");
        printf("\naddenv <VARNAME> <NEWVALUE>       : Add an environment variable.");
        printf("\npath                              : List all paths in the environment system variables 'Path'.");
        printf("\naddpath <NEW PATH>                : Add new path.");
        printf("\n\n");
    }
    else printf("\nBad command....\n\n");
    return 0;
}

int shell_exit(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    printf("\nSending kill signal to all child processes....\n\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    CloseHandle(hJob);
    exit(EXIT_FAILURE);
    return 0;
}

void shell_working(char **args){
    int shell_num_builtins = sizeof(builtin_str) / sizeof(char *);
    int i;
    int check = 0;
    for (i = 0; i < shell_num_builtins; i ++){
        if (strcmp(args[0], builtin_str[i]) == 0){
            check = 1;
            (*builtin_func[i])(args);
        }
    }
    if (check == 0){
        printf("\nBad command....\n\n");
    }
}

int shell_time(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    SYSTEMTIME lt = {0};
  
    GetLocalTime(&lt);
  
    wprintf(L"\nThe local time is: %02d:%02d:%02d\n\n", 
        lt.wHour, lt.wMinute, lt.wSecond);

    return 0;
}

int shell_date(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    SYSTEMTIME st = {0};
  
    GetLocalTime(&st);
  
    wprintf(L"\nToday is: %d-%02d-%02d\n\n", st.wYear, st.wMonth, st.wDay);

    return 0;
}

int get_current_directory(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    TCHAR infoBuf[BUFFER_SIZE];

    // Get the current working directory

    if(!GetCurrentDirectory(BUFFER_SIZE, infoBuf))
    printf("\nGet Current Directory failed!\n\n");

    printf("\nYour current directory is: %s\n\n", infoBuf);

    return 0;
}


int set_current_directory(char **args){
    if (args[2]){
        printf("\nBad command....\n\n");
        return 0;
    }
    TCHAR infoBuf[BUFFER_SIZE];

    if(!SetCurrentDirectory(args[1])) printf("\nSet Current Directory failed!\n\n");

    // Get the current working directory

    if(!GetCurrentDirectory(BUFFER_SIZE, infoBuf))
    printf("\nGet Current Directory() failed!\n\n");

    printf("\nYour current directory is: %s\n\n", infoBuf);

    return 0;
}

int list_files(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    WIN32_FIND_DATA data;
    HANDLE hFind; 
    char infoBuf[MAX_PATH];
    LARGE_INTEGER filesize;

    // Get the current working directory

    if(!GetCurrentDirectory(MAX_PATH, infoBuf)) printf("\nGet Current Directory failed!\n\n");

    printf("\nYour current directory is: %s\n\n", infoBuf);
    printf("========================================\n");
    strcat(infoBuf, "\\*");
    hFind = FindFirstFile(infoBuf, &data);      // FILE and DIRECTORY
    if ( hFind != INVALID_HANDLE_VALUE ) {
        do {
           filesize.LowPart = data.nFileSizeLow;
           filesize.HighPart = data.nFileSizeHigh;
           if (filesize.QuadPart != 0)
           printf("\n%-40s\t%ld bytes", data.cFileName, filesize.QuadPart);
           else printf("\n%-40s\t<DIR>", data.cFileName);
        } while (FindNextFile(hFind, &data));
        FindClose(hFind);
    }
    printf("\n\n");
    return 0;
}

int env(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    LPTSTR lpszVariable;
LPVOID lpvEnv;
 
// Get a pointer to the environment block.
lpvEnv = GetEnvironmentStrings();

// If the returned pointer is NULL, exit.

if (lpvEnv == NULL) printf("\nGet Environment Strings failed\n\n");
else printf("\nGet Environment Strings is OK.\n\n");

 

// Variable strings are separated by NULL byte, and the block is terminated by a NULL byte.

for (lpszVariable = (LPTSTR) lpvEnv; *lpszVariable; lpszVariable++)
{
while (*lpszVariable)
putchar(*lpszVariable++);
putchar('\n');
}

FreeEnvironmentStrings(lpvEnv);
return 0;

}

int addenv(char **args){
    char c;
    
    if (!args[1]){
        printf("\nBad command or filename....\n\n");
        return 0;
    }
    LPTSTR pszOldVal;
    DWORD dwRet, dwErr;
    BOOL fExist, fSuccess;
    pszOldVal = (LPTSTR) malloc(BUFFER_SIZE*sizeof(TCHAR));
    dwRet = GetEnvironmentVariable(args[1], pszOldVal, BUFFER_SIZE);
    if(0 == dwRet)
    {
        dwErr = GetLastError();
        if( ERROR_ENVVAR_NOT_FOUND == dwErr )
        {
            printf("\nEnvironment variable does not exist.\n\n");
            fExist=FALSE;
        }
    }
    else if (BUFFER_SIZE < dwRet)
    {
        pszOldVal = (LPTSTR) realloc(pszOldVal, dwRet*sizeof(TCHAR));   
        if(NULL == pszOldVal)
        {
            printf("\nOut of memory\n\n");
            return FALSE;
        }
        dwRet = GetEnvironmentVariable(args[1], pszOldVal, dwRet);
        if(!dwRet)
        {
            printf("\nGet Environment Variable failed (%d)\n\n", GetLastError());
            return FALSE;
        }
        else fExist=TRUE;
    }
    else fExist=TRUE;

    if (fExist){
        printf("\nVariable has already existed. Do you want to continue....(y/n) ");
        c = getchar();
        if (c == 'n' || c == 'N'){
            return 0;
        }
        printf("\n");
    }

    if (! SetEnvironmentVariable(args[1], args[2])) 
    {
        printf("\nSet Environment Variable failed (%d)\n\n", GetLastError()); 
        return FALSE;
    }

    free(pszOldVal);
    return 0;
}

int path(char **args){
    if (args[1]){
        printf("\nBad command....\n\n");
        return 0;
    }
    LPTSTR pszOldVal;
    DWORD dwRet, dwErr;
    BOOL fExist;
    pszOldVal = (LPTSTR) malloc(BUFFER_SIZE*sizeof(TCHAR));
    dwRet = GetEnvironmentVariable("Path", pszOldVal, BUFFER_SIZE);
    if(0 == dwRet)
    {
        dwErr = GetLastError();
        if( ERROR_ENVVAR_NOT_FOUND == dwErr )
        {
            printf("\nEnvironment variable does not exist.\n\n");
            fExist=FALSE;
        }
    }
    else if (BUFFER_SIZE < dwRet)
    {
        pszOldVal = (LPTSTR) realloc(pszOldVal, dwRet*sizeof(TCHAR));   
        if(NULL == pszOldVal)
        {
            printf("\nOut of memory\n\n");
            return FALSE;
        }
        dwRet = GetEnvironmentVariable("Path", pszOldVal, dwRet);
        if(!dwRet)
        {
            printf("\nGet Environment Variable failed (%d)\n\n", GetLastError());
            return FALSE;
        }
        else fExist=TRUE;
    }
    else fExist=TRUE;

    if (fExist){
        printf("\n%s\n\n", pszOldVal);
    }
    return 0;
}

int addpath(char **args){
    if (args[2]){
        printf("\nBad command....\n\n");
        return 0;
    }
    char* pszOldVal;
    DWORD dwRet, dwErr;
    BOOL fExist;
    pszOldVal = (char*) malloc(BUFFER_SIZE*sizeof(char));
    dwRet = GetEnvironmentVariable("Path", pszOldVal, BUFFER_SIZE);
    if(0 == dwRet)
    {
        dwErr = GetLastError();
        if( ERROR_ENVVAR_NOT_FOUND == dwErr )
        {
            printf("\nEnvironment variable does not exist.\n\n");
            fExist=FALSE;
        }
    }
    else if (BUFFER_SIZE < dwRet)
    {
        pszOldVal = (LPTSTR) realloc(pszOldVal, dwRet*sizeof(char));   
        if(NULL == pszOldVal)
        {
            printf("\nOut of memory\n\n");
            return FALSE;
        }
        dwRet = GetEnvironmentVariable("Path", pszOldVal, dwRet);
        if(!dwRet)
        {
            printf("\nGet Environment Variable failed (%d)\n\n", GetLastError());
            return FALSE;
        }
        else fExist=TRUE;
    }
    else fExist=TRUE;

    if (fExist){
        strcat(pszOldVal, ";");
        strcat(pszOldVal, args[1]);
    }
    if (! SetEnvironmentVariable("Path", pszOldVal)) 
    {
        printf("\nSet Environment Variable failed (%d)\n\n", GetLastError()); 
        return FALSE;
    }

    free(pszOldVal);
    return 0;
}