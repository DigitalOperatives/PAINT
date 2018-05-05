//_____  ProcessRecord.cpp _________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#include "PAINT.h"
#include "EventWriter.h"

VOID WINAPI ProcessEventRecordProperties(PEVENT_RECORD pEvent)
{
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    LPWSTR pwsEventGuid = NULL;
    ULONGLONG TimeStamp = 0;
    ULONGLONG Nanoseconds = 0;
    SYSTEMTIME st;
    SYSTEMTIME stLocal;
    FILETIME ft;
	HRESULT hr = S_OK;
    LPWSTR pStringGuid = NULL;
	char zero[8]; memset(zero, 0, 8);

	ConsoleMessage consoleMessage;
	consoleMessage.md5Text[0] = 0;

    // Skips the event if it is the event trace header. Log files contain this event
    // but real-time sessions do not. The event contains the same information as 
    // the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
    // the trace. 

    if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
        pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {
		PAINTSession::getInstance()->printAndWrite("\n\n\n------------------Processing Event Record ------------------\n");
		DecodeHeader(pEvent);

		consoleMessage.captureTime = Pcap::getCurrentTimeInMicroSeconds();

		if (pEvent->EventHeader.ProviderId.Data1 == 0x2ED6006E)
		{
			//PAINTSession::getInstance()->printAndWrite("Microsoft-Windows-NDIS-PacketCapture\n");
			consoleMessage.stackLayerString = "NDIS";
		}
		else if (pEvent->EventHeader.ProviderId.Data1 == 0x2F07E2EE)
		{
			//PAINTSession::getInstance()->printAndWrite("Microsoft-Windows-TCPIP\n");
			//if (!memcmp(pEvent->EventHeader.ActivityId.Data4, zero, 8) && pEvent->EventHeader.ActivityId.Data2 == 0 && pEvent->EventHeader.ActivityId.Data3 == 0)
			//	PAINTSession::getInstance()->printAndWrite("Found one!\n");
			consoleMessage.stackLayerString = "TCPIP";
		}
		else if (pEvent->EventHeader.ProviderId.Data1 == 0x83ED54F0)
		{
			consoleMessage.stackLayerString = "NetworkCorrelation";
			//PAINTSession::getInstance()->printAndWrite("Microsoft-Windows-Networking-Correlation\n");
		}
		else
			consoleMessage.stackLayerString = "Unknown";

		/*
		//Print Activity ID
		hr = StringFromCLSID(pEvent->EventHeader.ActivityId, &pStringGuid);
		if (FAILED(hr))
		{
			PAINTSession::getInstance()->wprintAndWrite(L"StringFromCLSID(ActivityId) failed with 0x%x\n", hr);
			status = hr;
			goto cleanup;
		}
		else
		{
			PAINTSession::getInstance()->wprintAndWrite(L"\nActivity ID: %s\n", pStringGuid);
			fwprintf(outputCSVFile, L"\"%s\",", pStringGuid);
			CoTaskMemFree(pStringGuid);
			pStringGuid = NULL;
		}
		*/

		//Print the process ID and path
		PAINTSession::getInstance()->printAndWrite("Process ID: %d", pEvent->EventHeader.ProcessId);

		consoleMessage.PID = pEvent->EventHeader.ProcessId;

		std::string processPath = getProcessPath(consoleMessage.PID , MAX_FILE_PATH_LEN, true);
		PAINTSession::getInstance()->printAndWrite(", Path: %s", processPath.c_str());
		consoleMessage.processPath = processPath;

		PAINTSession::getInstance()->printAndWrite("\n");

		consoleMessage.activityID = std::string(strguid(&pEvent->EventHeader.ActivityId));

		//if (!IsEqualGUID(pInfo->EventGuid, GUID_NULL))

        // Process the event. The pEvent->UserData member is a pointer to 
        // the event specific data, if it exists.

        status = GetEventInformation(pEvent, pInfo);

        if (ERROR_SUCCESS != status)
        {
            PAINTSession::getInstance()->wprintAndWrite(L"GetEventInformation failed with %lu\n", status);
            goto cleanup;
        }

		//printf("sendPath: 0x%016llX & 0x%016llX = 0x%016llX\n", pInfo->EventDescriptor.Keyword, g_sendPath, pInfo->EventDescriptor.Keyword & g_sendPath);
		//printf("sendPath: 0x%016llX & 0x%016llX = 0x%016llX\n", pInfo->EventDescriptor.Keyword, g_receivePath, pInfo->EventDescriptor.Keyword & g_receivePath);
		//printf("sendPath: 0x%016llX\n", (pInfo->EventDescriptor.Keyword & g_sendPath) || (pInfo->EventDescriptor.Keyword & g_receivePath));

		consoleMessage.in = pInfo->EventDescriptor.Keyword & g_receivePath;
		consoleMessage.out = pInfo->EventDescriptor.Keyword & g_sendPath;

		//Print provider name
		if (pInfo->ProviderNameOffset > 0)
		{
			PAINTSession::getInstance()->wprintAndWrite(L"Provider name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->ProviderNameOffset));
		}

		//Print the provider ID
		hr = StringFromCLSID(pInfo->ProviderGuid, &pStringGuid);
		if (FAILED(hr))
		{
			PAINTSession::getInstance()->wprintAndWrite(L"StringFromCLSID(ProviderGuid) failed with 0x%x\n", hr);
			status = hr;
			goto cleanup;
		}

		PAINTSession::getInstance()->wprintAndWrite(L"\nProvider GUID: %s\n", pStringGuid);
		CoTaskMemFree(pStringGuid);
		pStringGuid = NULL;

		if (pInfo->EventMessageOffset > 0)
		{
			PAINTSession::getInstance()->wprintAndWrite(L"Event message: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventMessageOffset));
			consoleMessage.message = std::wstring((LPWSTR((PBYTE)(pInfo) + pInfo->EventMessageOffset)));
		}

		if (pInfo->ActivityIDNameOffset > 0)
		{
			PAINTSession::getInstance()->wprintAndWrite(L"Activity ID name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->ActivityIDNameOffset));
		}

		if (pInfo->RelatedActivityIDNameOffset > 0)
		{
			PAINTSession::getInstance()->wprintAndWrite(L"Related activity ID name: %s\n", (LPWSTR)((PBYTE)(pInfo) + pInfo->RelatedActivityIDNameOffset));
		}

		//Print the event Guid
		/*
        hr = StringFromCLSID(pInfo->EventGuid, &pStringGuid);
        if (FAILED(hr))
        {
            PAINTSession::getInstance()->wprintAndWrite(L"StringFromCLSID(EventGuid) failed with 0x%x\n", hr);
            status = hr;
            goto cleanup;
        }
        PAINTSession::getInstance()->wprintAndWrite(L"\nEvent GUID: %s\n", pStringGuid);
        CoTaskMemFree(pStringGuid);
        pStringGuid = NULL;
		*/

        // Determine whether the event is defined by a MOF class, in an
        // instrumentation manifest, or a WPP template; to use TDH to decode
        // the event, it must be defined by one of these three sources.

		//Print out keywords
		PAINTSession::getInstance()->wprintAndWrite(L"Keyword mask: 0x%016llX\n", pInfo->EventDescriptor.Keyword);
		if (pInfo->KeywordsNameOffset)
		{
			LPWSTR pKeyword = (LPWSTR)((PBYTE)(pInfo) + pInfo->KeywordsNameOffset);

			for (; *pKeyword != 0; pKeyword += (wcslen(pKeyword) + 1))
				PAINTSession::getInstance()->wprintAndWrite(L"  Keyword name: %s\n", pKeyword);
		}

        if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
        {
            HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

            if (FAILED(hr))
            {
                PAINTSession::getInstance()->wprintAndWrite(L"StringFromCLSID failed with 0x%x\n", hr);
                status = hr;
                goto cleanup;
            }

            PAINTSession::getInstance()->wprintAndWrite(L"\nEvent GUID: %s\n", pwsEventGuid);
            CoTaskMemFree(pwsEventGuid);
            pwsEventGuid = NULL;

            PAINTSession::getInstance()->wprintAndWrite(L"Event version: %d\n", pEvent->EventHeader.EventDescriptor.Version);
            PAINTSession::getInstance()->wprintAndWrite(L"Event type: %d\n", pEvent->EventHeader.EventDescriptor.Opcode);
        }
        else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
        {
            PAINTSession::getInstance()->wprintAndWrite(L"Event ID: %d\n", pInfo->EventDescriptor.Id);
			consoleMessage.eventID = pInfo->EventDescriptor.Id;
        }
        else // Not handling the WPP case
        {
            goto cleanup;
        }

        // Print the time stamp for when the event occurred.
		/*
        ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
        ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

        TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
        Nanoseconds = (TimeStamp % 10000000) * 100;

        PAINTSession::getInstance()->wprintAndWrite(L"%02d/%02d/%02d %02d:%02d:%02d.%I64u\n", 
            stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);
		*/

        // If the event contains event-specific data use TDH to extract
        // the event data. For this example, to extract the data, the event 
        // must be defined by a MOF class or an instrumentation manifest.

        // Need to get the PointerSize for each event to cover the case where you are
        // consuming events from multiple log files that could have been generated on 
        // different architectures. Otherwise, you could have accessed the pointer
        // size when you opened the trace above (see pHeader->PointerSize).

        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
        {
            g_PointerSize = 4;
        }
        else
        {
            g_PointerSize = 8;
        }

        // Print the event data for all the top-level properties. Metadata for all the 
        // top-level properties come before structure member properties in the 
        // property information array. If the EVENT_HEADER_FLAG_STRING_ONLY flag is set,
        // the event data is a null-terminated string, so just print it.

        if (EVENT_HEADER_FLAG_STRING_ONLY == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY))
        {
            PAINTSession::getInstance()->wprintAndWrite(L"%s\n", (LPWSTR)pEvent->UserData);
        }
        else
        {
            for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
            {
                status = PrintProperties(pEvent, pInfo, i, NULL, 0, consoleMessage);
                if (ERROR_SUCCESS != status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"Printing top level properties failed.\n");
                    goto cleanup;
                }
            }
        }
    }

	//Write out the event.
	//This function will run the message through its state-machine and correlate things.
	EventWriter::getInstance()->writeEvent(consoleMessage);

cleanup:

    if (pInfo)
    {
        free(pInfo);
    }

    if (ERROR_SUCCESS != status)
    {
        //CloseTrace(g_openedTrace);
		PAINTSession::getInstance()->printAndWrite("cleanup called from ProcessEventRecordProperties function. CloseTrace.\n");
    }
}

const char* strguid(LPGUID guidPointer)
{
    static char stringBuffer[64];

    sprintf_s(stringBuffer, sizeof(stringBuffer),
               "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
               guidPointer->Data1, guidPointer->Data2, guidPointer->Data3,
               guidPointer->Data4[0], guidPointer->Data4[1],
               guidPointer->Data4[2], guidPointer->Data4[3],
               guidPointer->Data4[4], guidPointer->Data4[5],
               guidPointer->Data4[6], guidPointer->Data4[7]);
    return stringBuffer;
}

const char *
eventPropertyFlags(USHORT flags)
{
    if (flags & EVENT_HEADER_PROPERTY_XML)
        return "XML";
    if (flags & EVENT_HEADER_PROPERTY_FORWARDED_XML)
        return "forwarded XML";
    if (flags & EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG)
        return "legacy WMI MOF";
    return "none";
}

const char *
eventHeaderFlags(USHORT flags)
{
    static char buffer[128];
	size_t bufferLen = 128;
    char *p = &buffer[0];

    *p = '\0';
    if (flags & EVENT_HEADER_FLAG_EXTENDED_INFO)
        strcat_s(p, bufferLen, "extended info,");
    if (flags & EVENT_HEADER_FLAG_PRIVATE_SESSION)
        strcat_s(p, bufferLen, "private session,");
    if (flags & EVENT_HEADER_FLAG_STRING_ONLY)
        strcat_s(p, bufferLen, "string,");
    if (flags & EVENT_HEADER_FLAG_TRACE_MESSAGE)
        strcat_s(p, bufferLen, "TraceMessage,");
    if (flags & EVENT_HEADER_FLAG_NO_CPUTIME)
        strcat_s(p, bufferLen, "no cputime,");
    if (flags & EVENT_HEADER_FLAG_32_BIT_HEADER)
        strcat_s(p, bufferLen, "32bit,");
    if (flags & EVENT_HEADER_FLAG_64_BIT_HEADER)
        strcat_s(p, bufferLen, "64bit,");
    if (flags & EVENT_HEADER_FLAG_CLASSIC_HEADER)
        strcat_s(p, bufferLen, "classic,");
    buffer[strlen(buffer)] = '\0';
    return buffer;
}

void DecodeHeader(PEVENT_RECORD pEvent)
{
    PAINTSession::getInstance()->printAndWrite("Event HEADER (size=%u) flags=%s type=%s\npid=%ld tid=%ld eid=%u\n",
                pEvent->EventHeader.Size,
                eventHeaderFlags(pEvent->EventHeader.Flags),
                eventPropertyFlags(pEvent->EventHeader.EventProperty),
                pEvent->EventHeader.ProcessId, pEvent->EventHeader.ThreadId,
                pEvent->EventHeader.EventDescriptor.Id);
    if (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_PRIVATE_SESSION) {
        //PAINTSession::getInstance()->printAndWrite("Time processor=%"PRIu64"\n", pEvent->EventHeader.ProcessorTime);
    } 
	else {
        PAINTSession::getInstance()->printAndWrite("Time: sys=%lu usr=%lu\n",
                pEvent->EventHeader.KernelTime, pEvent->EventHeader.UserTime);
    }
    PAINTSession::getInstance()->printAndWrite("Event PROVIDER %s\n", strguid(&pEvent->EventHeader.ProviderId));
    PAINTSession::getInstance()->printAndWrite("Event ACTIVITY %s\n", strguid(&pEvent->EventHeader.ActivityId));

    if (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) {
        PAINTSession::getInstance()->printAndWrite("String: %ls\n\n", (wchar_t *)pEvent->UserData);
    }
}