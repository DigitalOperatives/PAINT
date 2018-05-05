//_____  PAINT.cpp ________________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: March 6, 2012
// Author		: Philip Yoon and Mike Myers
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//
// File Name    : PAINT.cpp
// File Purpose : The main file for PAINT
//__________________________________________________________________________

#include "PAINT.h"
#include "wingetopt.h"
#include "Pcap.h"
#include "PAINTSession.h"
#include "WiresharkPipe.h"

#include <fcntl.h>
#include <io.h>

// GUID that identifies your trace session.
// Remember to create your own session GUID.
static const GUID SessionGuid = { 0xae44cb98, 0xbd11, 0x4069, { 0x80, 0x93, 0x77, 0xe, 0xc9, 0x25, 0x8a, 0x00 } };
static const WCHAR TraceSessionName[] = L"PAINT Trace Session";

bool capture_child = FALSE; /* FALSE: standalone call, TRUE: this is an Wireshark capture child */
bool machine_readable = FALSE;

#define OPTSTRING "d:" "Df:ghi:" "Z:" "B:" "L:" "y:"

ConsoleMessage::ConsoleMessage()
{
	PID = -1;
	bytes=0;
	in = out = false;
	bytes=0;
}

// Start netsh trace capturing to kick start the ndiscap driver and whatever is 
// needed to receive NDIS-PacketCapture provider events. We will replace this 
// system call with something programmatic after figuring out how to set up the
// system to enable NDIS-PacketCapture provider events.
void TurnOnPacketCapture()
{
	int result = 0;

	// If we build in 32-bit, we must explicitly indicate the path of the
	// 64-bit version of netsh.exe. Otherwise we will be transparently
	// redirected to the 32-bit version of netsh.exe on 64-bit Windows, and
	// the 32-bit version lacks the "trace" command we are interested in.
#ifndef _PAINTWIN32
	//result = system("%windir%\\Sysnative\\netsh.exe trace start traceFile=TCPIP.etl provider=Microsoft-Windows-TCPIP capture=yes");
	result = system("%windir%\\Sysnative\\netsh.exe trace start maxSize=1 capture=yes");
#else
	result = system("netsh.exe trace start maxSize=1 capture=yes");
#endif

	if(result == -1)
	{
		PAINTSession::getInstance()->PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("Error: could not start packet capture driver.");
	}
}

// Tell netsh to shut down the ndiscap driver and whatever else is needed to
// properly turn off the packet capture. We will replace this with something
// programmatic after figuring out how to properly control the packet capture
// driver (it is undocumented Windows functionality).
void TurnOffPacketCapture()
{
	int result = 0;

	// If we build in 32-bit, we must explicitly indicate the path of the
	// 64-bit version of netsh.exe. Otherwise we will be transparently
	// redirected to the 32-bit version of netsh.exe on 64-bit Windows, and
	// the 32-bit version lacks the "trace" command we are interested in.
#ifndef _PAINTWIN32
	result = system("%windir%\\Sysnative\\netsh.exe trace stop");
#else
	result = system("netsh.exe trace stop");
#endif

	if(result == -1)
	{
		PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("Error: could not stop packet capture driver.");
	}
}

DWORD WINAPI MyThreadFunction( LPVOID lpParam ) 
{ 
	while (1)
	{
		int key = _getch();
		
		if (key == 102) // 'f = flush
		{
			PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("Flushing the ETW event buffer.\n");
			ControlTrace(NULL, TraceSessionName, evtTraceProperties, EVENT_TRACE_CONTROL_FLUSH);
		}
		else if (key == 113) //'q' = quit
		{
			PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("Quitting.\n");
			ControlTrace(NULL, TraceSessionName, evtTraceProperties, EVENT_TRACE_CONTROL_STOP);
			TurnOffPacketCapture();
			break;
		}
	}

    return 0; 
}

DWORD WINAPI NotifyFunction(LPVOID lpParam) 
{ 
	while (1)
	{
		Sleep(1000);
		Pcap::flushPacket();
	}

    return 0; 
} 

int Pad(int length)
{
	int m;
	int DataAlignment = 8; //align data on 8-byte boundaries
    int result = length;

    m = length % DataAlignment;
    if (m > 0)
        result = result + DataAlignment-m;
	
	return result;
}

int main(int argc, char* argv[])
{
	//listOpenTraceSessions();
	int opt;
	bool bListInterfaces = false;
	bool bListLayers = false;
	std::string s;

	HANDLE sig_pipe_handle = NULL;

	Pcap::forceWireless(false);

	while ((opt = getopt(argc, argv, OPTSTRING)) != -1) {
        switch (opt) {
        case 'h':        /* Print help and exit */
            printf("Printing help...\n");
            return 0;
            break;
        case 'D': 
			bListInterfaces = true;
			break;
		case 'L': 
			bListLayers = true;
			break;
		case 'y': 
			s.assign(optarg);
			if (s.substr(0, strlen("IEEE802_11")) == "IEEE802_11")
			{
				printf("Wireless mode\n");
				Pcap::forceWireless(true);
			}
			break;
		case 'Z':
			capture_child = TRUE;
            machine_readable = TRUE;

			_setmode(2, O_BINARY);
			break;
		}
	}

	if (bListInterfaces)
	{
		writeWireshark(2, 'S', NULL);

		printf("1. \\ETW-NDIS-PacketCapture\tEvent Tracing for Windows NDIS-PacketCapture\tALL,127.0.0.1\tnetwork\n");
		return 0;
	}

	if (bListLayers)
	{
		writeWireshark(2, 'S', NULL);

		printf("0\n");
		printf("1\tEN10MB\tEN10MB\tEthernet\n");
		printf("105\tForce802.11\tForce802.11\tProcessing 802.11 Captures\n");
		return 0;
	}

	ULONG status = ERROR_SUCCESS;
	g_openedTrace = (TRACEHANDLE)INVALID_HANDLE_VALUE;
	TRACEHANDLE hSession = (TRACEHANDLE)INVALID_HANDLE_VALUE;
	DWORD threadIdentifier;

	HANDLE hThread = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            MyThreadFunction,       // thread function name
            NULL,					// argument to thread function 
            0,                      // use default creation flags 
            &threadIdentifier);		// returns the thread identifier

	if (hThread != 0)
		PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("Thread %d created.\n", threadIdentifier);

	HANDLE hThread2 = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            NotifyFunction,			// thread function name
            NULL,					// argument to thread function 
            0,                      // use default creation flags 
            &threadIdentifier);		// returns the thread identifier

	if (hThread2 != 0)
		PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("Thread %d created.\n", threadIdentifier);

	//Headers for the CSV file
	PAINTSession::getInstance()->CSVPrintAndWrite("\"Event Number\",\"Stack Layer\",\"PID\",\"Process Path/Name\",\"ActivityID\",\"EventID\",\"Bytes\",\"In?\",\"Out?\",\"Event\"\n");

	status = ERROR_SUCCESS;

	TurnOnPacketCapture();

	writeWireshark(2, 'F', "PAINTOutput.pcap");

	// Allocate and initialize an EVENT_TRACE_PROPERTIES struct to define 
	// a tracing session. The size allocated is the size of the struct
	// plus enough space for two strings (session name and log file name).
	ULONG SizeNeeded = Pad(sizeof(EVENT_TRACE_PROPERTIES)) + Pad(sizeof(TraceSessionName)+sizeof(TCHAR));
						//(2 * MAXSTR * sizeof(TCHAR));
	evtTraceProperties = (PEVENT_TRACE_PROPERTIES)malloc(SizeNeeded);
	if (evtTraceProperties == NULL)
	{
		PAINTSession::getInstance()->wprintAndWrite(L"Malloc failed; out of memory.\n");
		return EXIT_FAILURE;
	}

	ZeroMemory(evtTraceProperties, SizeNeeded);
	evtTraceProperties->Wnode.BufferSize = SizeNeeded;
	evtTraceProperties->Wnode.Guid = SessionGuid; //SystemTraceControlGuid
	evtTraceProperties->Wnode.ClientContext = 1; //QPC clock resolution
	evtTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	evtTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	evtTraceProperties->FlushTimer = 1; //flushes buffered events every 1 sec.
	evtTraceProperties->LoggerNameOffset = 0;
	evtTraceProperties->LogFileNameOffset = 0; //indicates real-time consuming

	status = StartTrace(&hSession, TraceSessionName, evtTraceProperties);
	if(status == ERROR_ALREADY_EXISTS)
	{
		//PAINTSession::getInstance()->wprintAndWrite(L"Trace provider session already exists. Continuing.\n");
		//return hSession;
		status = StopTrace(hSession, TraceSessionName, evtTraceProperties);
		status = StartTrace(&hSession, TraceSessionName, evtTraceProperties);
		PAINTSession::getInstance()->wprintAndWrite(L"StartTrace returned status code %lu.\n", GetLastError());
	}

	else if(status != ERROR_SUCCESS)
	{
		PAINTSession::getInstance()->wprintAndWrite(L"StartTrace failed with status code %lu.\n", GetLastError());
		if (status == ERROR_ACCESS_DENIED)
			PAINTSession::getInstance()->wprintAndWrite(L"Access Denied: You must be administrator to control trace sessions.\n");
		return EXIT_FAILURE;
	}

	// Turn on the tracing:
	// The enable flags are specified per-provider, allowing fine-grained tracing 
	// of specific events. Enabling all keywords for now.

	//Can get the keyword flags to take out keywords ut:TcpipInterface, ut:TcpipDiagnosis, ut:Global
	//Rejecting them in the record processor
	status = EnableTraceEx2(hSession, &TCPIP_Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,  0, 0, 0, NULL);
	
	//Networking Correlation
	status = EnableTraceEx2(hSession, &NetCorrel_Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,  0, 0, 0, NULL);
	
	//NDIS-PacketCapture provider. This will give us the actual frame captures
	status = EnableTraceEx2(hSession, &NDIS_PC_Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,  0, 0, 0, NULL);

	if(status != ERROR_SUCCESS)
	{
		PAINTSession::getInstance()->wprintAndWrite(L"EnableTrace failed with %lu.\n", GetLastError());
		if (status == ERROR_ACCESS_DENIED)
			PAINTSession::getInstance()->wprintAndWrite(L"Access Denied: You must be administrator to control trace sessions.\n");
		return EXIT_FAILURE;
	}
	else
	{
		PAINTSession::getInstance()->wprintAndWrite(L"Trace provider session started.\n");
	}

	if (hSession == (TRACEHANDLE)INVALID_HANDLE_VALUE)
	{
		PAINTSession::getInstance()->wprintAndWrite(L"TurnOnTracing failed.\n");
		goto cleanup;
	}

	// Define the trace session by filling out an EVENT_TRACE_LOGFILE 
	// structure. The structure specifies the source from which to consume
	// events (from a log file or the session in real time) and specifies 
	// the callbacks the consumer wants to use to receive the events.
	EVENT_TRACE_LOGFILE evtLogFile;
	ZeroMemory(&evtLogFile, sizeof(EVENT_TRACE_LOGFILE));
	evtLogFile.LoggerName = (LPWSTR)TraceSessionName;
	evtLogFile.LogFileName = NULL;	// indicates a real-time session rather than a logfile
	evtLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    evtLogFile.BufferCallback = (PEVENT_TRACE_BUFFER_CALLBACK) (ProcessBuffer);
	evtLogFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK) (ProcessEventRecordProperties);

	// Get a handle to the trace session:
	g_openedTrace = OpenTrace(&evtLogFile);
	if (g_openedTrace == (TRACEHANDLE)INVALID_HANDLE_VALUE)
    {
        PAINTSession::getInstance()->wprintAndWrite(L"OpenTrace failed with status code %lu.\n", GetLastError());
		if (status == ERROR_ACCESS_DENIED)
			PAINTSession::getInstance()->wprintAndWrite(L"Access Denied: you must be administrator to listen for trace events.\n");
        goto cleanup;
    }

	// ProcessTrace() blocks current execution and sits there until the session
	// ends or BufferCallback returns FALSE. Meanwhile, your registered event 
	// callback function is invoked whenever an event is available in the 
	// session buffer.
	status = ProcessTrace(&g_openedTrace, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
    {
        PAINTSession::getInstance()->wprintAndWrite(L"ProcessTrace failed with status code %lu.\n", status);
		if (status == ERROR_ACCESS_DENIED)
			PAINTSession::getInstance()->wprintAndWrite(L"Access Denied: you must be administrator to listen for trace events.\n");
        else if (status == ERROR_WMI_INSTANCE_NOT_FOUND)
            PAINTSession::getInstance()->wprintAndWrite(L"Tracing session instance by the specified name not found among existing ETW providers.\n");
        goto cleanup;
    }

cleanup:
	if (hSession != (TRACEHANDLE)INVALID_HANDLE_VALUE)
	{
		TurnOffTracing(hSession);
	}

	if (g_openedTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE)
    {
		PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("cleanup called from main function. CloseTrace.\n");
        CloseTrace(g_openedTrace);
    }

	return 0;
}

// Implements ETW controller functionality to stop the ETW provider.
void TurnOffTracing(TRACEHANDLE hSession)
{
	ULONG status = ERROR_SUCCESS;

	//Tell the trace provider to stop providing events: 
	status = ControlTrace(hSession, NULL, evtTraceProperties, EVENT_TRACE_CONTROL_STOP);
	if(status != ERROR_SUCCESS)
	{
		PAINTSession::getInstance()->wprintAndWrite(L"ControlTrace() failed with status code %lu.\n", GetLastError());
	}

	free(evtTraceProperties);
}


// Taken from MSDN example: http://msdn.microsoft.com/en-us/library/ee441325(v=vs.85).aspx
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO &pInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;

    // Retrieve the required buffer size for the event metadata:
    status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

    if (status == ERROR_INSUFFICIENT_BUFFER)
    {
        pInfo = (TRACE_EVENT_INFO*) malloc(BufferSize);
        if (pInfo == NULL)
        {
            PAINTSession::getInstance()->wprintAndWrite(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the event metadata:
        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    }
	
    if (status != ERROR_SUCCESS)
    {
        PAINTSession::getInstance()->wprintAndWrite(L"TdhGetEventInformation failed with 0x%x.\n", status);

		if (status == ERROR_NOT_FOUND)
			PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("ERROR: The schema for the event was not found.\n");
		else if (status == ERROR_INVALID_PARAMETER)
			PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("ERROR: One or more parameters are invalid.\n");
		else if (status == ERROR_FILE_NOT_FOUND)
			PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("ERROR: The resourceFileName attribute in the manifest contains the location of the\
						  provider binary. When you register the manifest, the location is written to the registry.\
						  TDH was unable to find the binary based on the registered location.\n");
		else if (status == ERROR_WMI_SERVER_UNAVAILABLE)
			PAINTSession::getInstance()->PAINTSession::getInstance()->printAndWrite("ERROR: The WMI service is not available..\n");
    }

cleanup:
    return status;
}

// This callback receives and processes all events (including the header event) 
// from the real-time session. However, you do not implement this callback if 
// you use the trace data helper functions to parse the event data or you want
// to retrieve metadata about the event. In that case, you use the EventRecord
// callback, below.
void WINAPI ProcessEvent(PEVENT_TRACE pEvent)
{
}

// This callback receives and processes summary information about the current
// buffer, such as events lost. ETW also calls the callback after delivering 
// all events in the buffer to the consumer.
ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer)
{
	PAINTSession::getInstance()->wprintAndWrite(L"ProcessBuffer() was called.\n");
	return true;
}