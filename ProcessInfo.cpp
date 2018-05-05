//_____  ProcessInfo.cpp __________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: March 6, 2012
// Author		: Philip Yoon and Mike Myers
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//
// File Name    : ProcessInfo.cpp
// File Purpose : Get the path/file name of the PID
// Notes        : Requires psapi.lib
//__________________________________________________________________________

#include "windows.h"
#include "stdio.h"
#include "psapi.h"
#include "PAINT.h"

#pragma comment(lib, "psapi.lib") 

std::string getProcessPath(int pid, int maxPath, bool nameOnly)
{
	static char processPathString[MAX_FILE_PATH_LEN];
	std::string returnString;

    HANDLE Handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );
    if (Handle) 
    {
		DWORD maxPathDWORD = maxPath;
		if (QueryFullProcessImageNameA(Handle, 0, processPathString, &maxPathDWORD))
        {
            // At this point, buffer contains the full path to the executable
			returnString = std::string(processPathString);
			if (nameOnly)
			{
				std::vector<std::string> tokens = split(returnString, '\\');
				if (tokens.size() > 1)
					returnString = tokens[tokens.size() - 1];
			}
        }
        else
        {
            // You better call GetLastError() here
			returnString = "Process Name N/A";
        }
        CloseHandle(Handle);
    }
    return returnString;
}