//_____  TraceSessions.cpp _________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: March 6, 2012
// Author		: Philip Yoon and Mike Myers
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//
// File Name    : TraceSessions.cpp
// File Purpose : List active trace session on current machine
//__________________________________________________________________________


#include "PAINT.h"

void listOpenTraceSessions(void)
{
    ULONG status = ERROR_SUCCESS;
    PEVENT_TRACE_PROPERTIES pSessions[MAX_SESSIONS];    // Array of pointers to property structures
    PEVENT_TRACE_PROPERTIES pBuffer = NULL;             // Buffer that contains all the property structures
    ULONG SessionCount = 0;                             // Actual number of sessions started on the computer
    ULONG BufferSize = 0;
    ULONG PropertiesSize = 0;
    WCHAR SessionGuid[50];

    // The size of the session name and log file name used by the
    // controllers are not known, therefore create a properties structure that allows
    // for the maximum size of both.

    PropertiesSize = sizeof(EVENT_TRACE_PROPERTIES) +
        (MAX_SESSION_NAME_LEN*sizeof(WCHAR)) +
        (MAX_LOGFILE_PATH_LEN*sizeof(WCHAR));

    BufferSize = PropertiesSize * MAX_SESSIONS;

    pBuffer = (PEVENT_TRACE_PROPERTIES) malloc(BufferSize);

    if (pBuffer)
    {
        ZeroMemory(pBuffer, BufferSize);

        for (USHORT i = 0; i < MAX_SESSIONS; i++)
        {
            pSessions[i] = (EVENT_TRACE_PROPERTIES*)((BYTE*)pBuffer + (i*PropertiesSize));
            pSessions[i]->Wnode.BufferSize = PropertiesSize;
            pSessions[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            pSessions[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_SESSION_NAME_LEN*sizeof(WCHAR));
        }
    }
    else
    {
        PAINTSession::getInstance()->wprintAndWrite(L"Error allocating memory for properties.\n");
        goto cleanup;
    }

    status = QueryAllTraces(pSessions, (ULONG)MAX_SESSIONS, &SessionCount);

    if (ERROR_SUCCESS == status || ERROR_MORE_DATA == status)
    {
        PAINTSession::getInstance()->wprintAndWrite(L"Requested session count, %d. Actual session count, %d.\n\n", MAX_SESSIONS, SessionCount);

        for (USHORT i = 0; i < SessionCount; i++)
        {
			if (i == 13)
				PAINTSession::getInstance()->printAndWrite("13\n");
            StringFromGUID2(pSessions[i]->Wnode.Guid, SessionGuid, (sizeof(SessionGuid) / sizeof(SessionGuid[0])));
			/*
                PAINTSession::getInstance()->wprintAndWrite(L"Session GUID: %s\nSession ID: %d\nSession name: %s\nLog file: %s\n"
                    L"min buffers: %d\nmax buffers: %d\nbuffers: %d\nbuffers written: %d\n"
                    L"buffers lost: %d\nevents lost: %d\n\n",
                    SessionGuid,
                    pSessions[i]->Wnode.HistoricalContext,
                    (LPWSTR)((char*)pSessions[i] + pSessions[i]->LoggerNameOffset),
                    (LPWSTR)((char*)pSessions[i] + pSessions[i]->LogFileNameOffset),
                    pSessions[i]->MinimumBuffers,
                    pSessions[i]->MaximumBuffers,
                    pSessions[i]->NumberOfBuffers,
                    pSessions[i]->BuffersWritten,
                    pSessions[i]->LogBuffersLost,
                    pSessions[i]->EventsLost);
					*/
				 PAINTSession::getInstance()->wprintAndWrite(L"Session name: %s\n\n",
                    (LPWSTR)((char*)pSessions[i] + pSessions[i]->LoggerNameOffset));
        }
    }
    else
    {
        PAINTSession::getInstance()->wprintAndWrite(L"Error calling QueryAllTraces, %d.\n", status);
        goto cleanup;
    }

cleanup:

    if (pBuffer)
    {
        free(pBuffer);
        pBuffer = NULL;
    }
}