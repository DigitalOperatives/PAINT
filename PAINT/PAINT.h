//_____  PAINT.h __________________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: March 6, 2012
// Author		: Philip Yoon and Mike Myers
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//
// File Name    : PAINT.h
// File Purpose : Currently the header file for all PAINT source files
//__________________________________________________________________________


#ifndef ANOTHER_CONSUMER_H
#define ANOTHER_CONSUMER_H

#define INITGUID

#include <wbemidl.h>
#include <in6addr.h>
#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <process.h>
#include <ctype.h>
#include <strsafe.h>
#include <stdio.h>
#include <wmistr.h>		// Required for EWT
#include <evntrace.h>	// Required for EWT
#include <tdh.h>		// Required for TDH (event parsing)
#pragma comment(lib, "tdh.lib")  // Required for TDH (event parsing)
#pragma comment(lib, "ws2_32.lib")  // For ntohs function
#include <evntcons.h>

//#include "../../PolarSSL/md5.h"
#include "Pcap.h"

#include <string>
#include <vector>
#include <sstream>

#include "Util.h"
#include "PAINTSession.h"

// Constants:
#define MAXSTR 1024     // as specified in documentation for StartTrace() API.
#define MAX_NAME 256
#define MAX_SESSIONS 64
#define MAX_SESSION_NAME_LEN 1024
#define MAX_LOGFILE_PATH_LEN 1024
#define MAX_FILE_PATH_LEN 2048

typedef LPTSTR (NTAPI *PIPV6ADDRTOSTRING)(
  const IN6_ADDR *Addr,
  LPTSTR S
);

 #define PH_IPV4_NETWORK_TYPE 0x1
 #define PH_IPV6_NETWORK_TYPE 0x2
 #define PH_NETWORK_TYPE_MASK 0x3
 
 #define PH_TCP_PROTOCOL_TYPE 0x10
 #define PH_UDP_PROTOCOL_TYPE 0x20
 #define PH_PROTOCOL_TYPE_MASK 0x30
 
 #define PH_NO_NETWORK_PROTOCOL 0x0
 #define PH_TCP4_NETWORK_PROTOCOL (PH_IPV4_NETWORK_TYPE | PH_TCP_PROTOCOL_TYPE)
 #define PH_TCP6_NETWORK_PROTOCOL (PH_IPV6_NETWORK_TYPE | PH_TCP_PROTOCOL_TYPE)
 #define PH_UDP4_NETWORK_PROTOCOL (PH_IPV4_NETWORK_TYPE | PH_UDP_PROTOCOL_TYPE)
 #define PH_UDP6_NETWORK_PROTOCOL (PH_IPV6_NETWORK_TYPE | PH_UDP_PROTOCOL_TYPE)

class ConsoleMessage
{
public:
	ConsoleMessage();

	int PID;
	std::string stackLayerString;
	std::string processPath;
	std::string activityID;
	int eventID;
	std::wstring message;
	unsigned long long captureTime;  // Event timestamp in microseconds, used for PCAP, only applicable for NDIS events
									 //This time is also relative to start of capture, just like how PCAP expects it
	bool in;
	bool out;
	int bytes;
	std::wstring sourceProvider;
	std::wstring context;
	std::vector<char> fragment;
	std::wstring TCB;
	std::wstring newTCPState;
	unsigned char md5[16];
	unsigned char md5Text[33];
	std::vector<std::wstring> messageParameters;
};

//ut:TcpipInterface, ut:TcpipDiagnosis, ut:Global
static char g_unwantedTCPIPKeysChars[] = {(char)0x80, (char)0x00, (char)0x00, (char)0x40, (char)0x00, (char)0x00, (char)0x00, (char)0x90};
static unsigned long long g_unwantedTCPIPKeys = 0x8000004000000090; //*(long long*)(g_unwantedTCPIPKeysChars);
static unsigned long long g_sendPath = 0x0000000100000000;
static unsigned long long g_receivePath = 0x0000000200000000;

// Used to determine the data size of property values that contain a
// Pointer value. The value will be 4 or 8.
static USHORT g_PointerSize = 0;

// Used to calculate CPU usage

static ULONG g_TimerResolution = 0;

// Used to determine if the session is a private session or kernel session.
// You need to know this when accessing some members of the EVENT_TRACE.Header
// member (for example, KernelTime or UserTime).

static BOOL g_bUserMode = FALSE;

// Handle to the trace file that you opened.
static TRACEHANDLE g_openedTrace = 0;  


// Global variables (refactor later):
static PEVENT_TRACE_PROPERTIES evtTraceProperties;
// See <guiddef.h> for the GUID structure definition.
// Find the GUIDs for a particular ETW provider by using logman:
//    logman query providers | findstr /I WinHTTP
// Microsoft-Windows-WinHttp = {7D44233D-3055-4B9C-BA64-0D47CA40A232}

// Microsoft-Windows-NDIS-PacketCapture = {2ED6006E-4729-4609-B4 23-3E E7 BC D6 78 EF}
static const GUID NDIS_PC_Guid = {0x2ED6006E,0x4729,0x4609,{0xB4,0x23,0x3E,0xE7,0xBC,0xD6,0x78,0xEF}};
static const WCHAR NDIS_PC_Name[] = L"Microsoft-Windows-NDIS-PacketCapture";

// Microsoft-Windows-NDIS {CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9} 
static const GUID NDIS_Guid = {0xCDEAD503,0x17F5,0x4A3E,{0xB7, 0xAE, 0xDF, 0x8C, 0xC2, 0x90, 0x2E, 0xB9}};
static const WCHAR NDIS_Name[] = L"Microsoft-Windows-NDIS";

// NDIS Tracing {DD7A21E6-A651-46D4-B7C2-66543067B869} 
static const GUID NDISTracing_Guid = {0xDD7A21E6,0xA651,0x46D4,{0xB7, 0xC2, 0x66, 0x54, 0x30, 0x67, 0xB8, 0x69}};
static const WCHAR NDISTracing_Name[] = L"NDIS Tracing";

static const GUID NDISCAP_Guid = {0xEA24CD6C, 0xD17A, 0x4348, {0x91, 0x90, 0x09, 0xF0, 0xD5, 0xBE, 0x83, 0xDD}};
static const WCHAR NDISCAP_Name[] = L"NDIS-Capture-LightWeight-Filter";

// Microsoft-Windows-WinSock-AFD = {E53C6823-7BB8-44BB-90DC-3F86090D48A6}
static const GUID WinSock_Guid = {0xE53C6823,0x7BB8,0x44BB,{0x90,0xDC,0x3F,0x86,0x09,0x0D,0x48,0xA6}};
static const WCHAR WinSock_Name[] = L"Microsoft-Windows-WinSock-AFD";

// Microsoft-Windows-Networking-Correlation {83ED54F0-4D48-4E45-B16E-726FFD1FA4AF}
static const GUID NetCorrel_Guid = {0x83ED54F0,0x4D48,0x4E45,{0xB1, 0x6E, 0x72, 0x6F, 0xFD, 0x1F, 0xA4, 0xAF}};
static const WCHAR NetCorrel_Name[] = L"Microsoft-Windows-Networking-Correlation";

// Microsoft-Windows-TCPIP = {2F07E2EE-15DB-40F1-90EF-9D 7B A2 82 18 8A}
static const GUID TCPIP_Guid = {0x2F07E2EE,0x15DB,0x40F1,{0x90,0xEF,0x9D,0x7B,0xA2,0x82,0x18,0x8A}};
static const WCHAR TCPIP_Name[] = L"Microsoft-Windows-TCPIP";

// Microsoft-Windows-WinHttp = {7D44233D-3055-4B9C-BA64-0D47CA40A232}
static const GUID HTTP_Guid = {0x7D44233D,0x3055,0x4B9C,{0xBA,0x64,0x0D,0x47,0xCA,0x40,0xA2,0x32}};
static const WCHAR HTTP_Name[] = L"Microsoft-Windows-WinHttp";

//Microsoft-Windows-Diagnostics-Networking {36C23E18-0E66-11D9-BBEB-505054503030}
static const GUID DiagNetwork_Guid = {0x36C23E18,0x0E66,0x11D9,{0xBB, 0xEB, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}};
static const WCHAR DiagNetwork_Name[] = L"Microsoft-Windows-Diagnostics-Networking";

// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
static const GUID KernelNetwork_Guid = {0x7DD42A49,0x5329,0x4832,{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}};
static const WCHAR KernelNetwork_Name[] = L"Microsoft-Windows-Kernel-Network";

// Strings that represent the source of the event metadata:
static WCHAR* pSource[] = {L"XML instrumentation manifest", L"WMI MOF class", L"WPP TMF file"};

static const WCHAR StrLocalAddress[] = L"LocalAddress";
static const WCHAR StrRemoteAddress[] = L"RemoteAddress";
static const WCHAR StrLocalSockAddress[] = L"LocalSockAddr";
static const WCHAR StrRemoteSockAddress[] = L"RemoteSockAddr";
static const WCHAR StrPid[] = L"Pid";

void DecodeHeader(PEVENT_RECORD pEvent);
void WINAPI ProcessEvent(PEVENT_TRACE pEvent);
void WINAPI ProcessEventRecord(PEVENT_RECORD pEvent);
VOID WINAPI ProcessEventRecordProperties(PEVENT_RECORD pEvent);

ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILE pBuffer);
TRACEHANDLE TurnOnTracing();
void TurnOffTracing(TRACEHANDLE hSession);
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO &pInfo);
DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pInfo, DWORD i, USHORT indent);

//PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex, ConsoleMessage&);
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo, std::wstring&);
std::wstring PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
const char* strguid(LPGUID guidPointer);

void listOpenTraceSessions(void);

#endif