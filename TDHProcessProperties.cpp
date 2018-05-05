//_____  TDHProcessProperties.cpp __________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: March 6, 2012
// Author		: Philip Yoon and Mike Myers
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//
// File Name    : TDHProcessProperties.cpp
// File Purpose : This file is responsible for parsing out the 
//                event properties using Trace Data Helper
//__________________________________________________________________________

#include "PAINT.h"

// Taken from MSDN example: http://msdn.microsoft.com/en-us/library/ee441325(v=vs.85).aspx
DWORD PrintPropertyMetadata(TRACE_EVENT_INFO* pInfo, DWORD i, USHORT indent)
{
	DWORD status = ERROR_SUCCESS;
    DWORD j = 0;
    DWORD lastMember = 0;  // Last member of a structure

    // Print property name.

    PAINTSession::getInstance()->wprintAndWrite(L"%*s%s", indent, L"", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset));

    // If the property is an array, the property can define the array size or it can
    // point to another property whose value defines the array size. The PropertyParamCount
    // flag tells you where the array size is defined.

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        PAINTSession::getInstance()->wprintAndWrite(L" (array size is defined by %s)", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset));
    }
    else
    {
        if (pInfo->EventPropertyInfoArray[i].count > 1)
            PAINTSession::getInstance()->wprintAndWrite(L" (array size is %lu)", pInfo->EventPropertyInfoArray[i].count);
    }


    // If the property is a buffer, the property can define the buffer size or it can
    // point to another property whose value defines the buffer size. The PropertyParamLength
    // flag tells you where the buffer size is defined.

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
    {
        j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        PAINTSession::getInstance()->wprintAndWrite(L" (size is defined by %s)", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset));
    }
    else
    {
        // Variable length properties such as structures and some strings do not have
        // length definitions.

        if (pInfo->EventPropertyInfoArray[i].length > 0)
            PAINTSession::getInstance()->wprintAndWrite(L" (size is %lu bytes)", pInfo->EventPropertyInfoArray[i].length);
        else
            PAINTSession::getInstance()->wprintAndWrite(L" (size  is unknown)");
    }

    PAINTSession::getInstance()->wprintAndWrite(L"\n");


    // If the property is a structure, print the members of the structure.
    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
    {
        PAINTSession::getInstance()->wprintAndWrite(L"%*s(The property is a structure and has the following %hu members:)\n", 4, L"",
            pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers);

        lastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex + 
            pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

        for (j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < lastMember; j++)
        {
            PrintPropertyMetadata(pInfo, j, 4);
        }
    }
    else
    {
        // You can use InType to determine the data type of the member and OutType
        // to determine the output format of the data.

        if (pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset)
        {
            // You can pass the name to the TdhGetEventMapInformation function to 
            // retrieve metadata about the value map.

            PAINTSession::getInstance()->wprintAndWrite(L"%*s(Map attribute name is %s)\n", indent, L"", 
                (PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset));
        }
    }

    return status;
}

// Get the length of the property data. For MOF-based events, the size is inferred from the data type
// of the property. For manifest-based events, the property can specify the size of the property value
// using the length attribute. The length attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size. If the property does not include the 
// length attribute, the size is inferred from the data type. The length will be zero for variable
// length, null-terminated strings and structures.

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    // If the property is a binary blob and is defined in a manifest, the property can 
    // specify the blob's size or it can point to another property that defines the 
    // blob's size. The PropertyParamLength flag tells you where the blob's size is defined.

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
    {
        DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
        *PropertyLength = (USHORT)Length;
    }
    else
    {
        if (pInfo->EventPropertyInfoArray[i].length > 0)
        {
            *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
        }
        else
        {
            // If the property is a binary blob and is defined in a MOF class, the extension
            // qualifier is used to determine the size of the blob. However, if the extension 
            // is IPAddrV6, you must set the PropertyLength variable yourself because the 
            // EVENT_PROPERTY_INFO.length field will be zero.

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                *PropertyLength = 16;//(USHORT)sizeof(IN6_ADDR);
            }
            else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                     TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                     (pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
            {
                *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
            }
            else
            {
                PAINTSession::getInstance()->wprintAndWrite(L"Unexpected length of 0 for intype %d and outtype %d\n", 
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

                status = ERROR_EVT_INVALID_EVENT_DATA;
                goto cleanup;
            }
        }
    }

cleanup:

    return status;
}


// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }

    return status;
}


// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    // Retrieve the required buffer size for the map info.

    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO) malloc(MapSize);
        if (pMapInfo == NULL)
        {
            PAINTSession::getInstance()->wprintAndWrite(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the map info.

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace(pMapInfo);
        }
    }
    else
    {
        if  (ERROR_NOT_FOUND == status)
        {
            status = ERROR_SUCCESS; // This case is okay.
        }
        else
        {
            PAINTSession::getInstance()->wprintAndWrite(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
        }
    }

cleanup:

    return status;
}


// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    DWORD ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}


// Print the property.

DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex, ConsoleMessage& consoleMessage)
{
    DWORD status = ERROR_SUCCESS;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ULONG DescriptorsCount = 0;
    DWORD PropertySize = 0;
    PBYTE pData = NULL;
	bool bIPAddress = false;
	bool pid = false;
	bool bNewTCPState = false;
	bool numBytes = false;
	bool fragment = false;
	bool sourceProvider = false;
	bool context = false;
	bool bTCB = false;
	static WCHAR ipAddress[256];

    // Get the size of the array if the property is an array.

    status = GetArraySize(pEvent, pInfo, i, &ArraySize);

    for (USHORT k = 0; k < ArraySize; k++)
    {
        PAINTSession::getInstance()->wprintAndWrite(L"%*s%s: ", (pStructureName) ? 4 : 0, L"", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset));

		//This is probably a hack - there's probably a better way to figure out the data type.
		//The data types in the TDH spec are too general to cover these cases
		if (!memcmp(StrLocalAddress, (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(StrLocalAddress)))
			bIPAddress = true;
		else if (!memcmp(StrRemoteAddress, (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(StrRemoteAddress)))
			bIPAddress = true;
		else if (!memcmp(StrLocalSockAddress, (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(StrLocalSockAddress)))
			bIPAddress = true;
		else if (!memcmp(StrRemoteSockAddress, (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(StrRemoteSockAddress)))
			bIPAddress = true;
		else if (!memcmp(L"NewState", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"NewState")))
			bNewTCPState = true;
		else if (!memcmp(StrPid, (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(StrPid)))
			pid = true;
		else if (!memcmp(L"ProcessId", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"ProcessId")))
			pid = true;
		else if (!memcmp(L"NumBytes", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"NumBytes")))
			numBytes = true;
		else if (!memcmp(L"FragmentSize", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"FragmentSize")))
			numBytes = true;
		else if (!memcmp(L"Fragment", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"Fragment")))
			fragment = true;
		else if (!memcmp(L"SourceProvider", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"SourceProvider")))
			sourceProvider = true;
		else if (!memcmp(L"Context", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"Context")))
			context = true;
		else if (!memcmp(L"Tcb", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"Tcb")))
			bTCB = true;
		else if (!memcmp(L"PortAcquirer", (PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset, sizeof(L"PortAcquirer")))
			bTCB = true;

        // If the property is a structure, print the members of the structure.

        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
        {
            PAINTSession::getInstance()->wprintAndWrite(L"\n");

            LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex + 
                pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

            for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
            {
                status = PrintProperties(pEvent, pInfo, j, (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset), k, consoleMessage);
                if (ERROR_SUCCESS != status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"Printing the members of the structure failed.\n");
                    goto cleanup;
                }
            }
        }
        else
        {
            ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));

            // To retrieve a member of a structure, you need to specify an array of descriptors. 
            // The first descriptor in the array identifies the name of the structure and the second 
            // descriptor defines the member of the structure whose data you want to retrieve. 

            if (pStructureName)
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)pStructureName;
                DataDescriptors[0].ArrayIndex = StructIndex;
                DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[1].ArrayIndex = k;
                DescriptorsCount = 2;
            }
            else
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[0].ArrayIndex = k;
                DescriptorsCount = 1;
            }

            // The TDH API does not support IPv6 addresses. If the output type is TDH_OUTTYPE_IPV6,
            // you will not be able to consume the rest of the event. If you try to consume the
            // remainder of the event, you will get ERROR_EVT_INVALID_EVENT_DATA.

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                PAINTSession::getInstance()->wprintAndWrite(L"The event contains an IPv6 address. Skipping event.\n");
                status = ERROR_EVT_INVALID_EVENT_DATA;
                break;
            }
            else
            {
                status = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &PropertySize);

                if (ERROR_SUCCESS != status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"TdhGetPropertySize failed with %lu\n", status);
                    goto cleanup;
                }

                pData = (PBYTE)malloc(PropertySize);

                if (NULL == pData)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"Failed to allocate memory for property data\n");
                    status = ERROR_OUTOFMEMORY;
                    goto cleanup;
                }

                status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);
				if (ERROR_SUCCESS != status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"GetMapInfo failed\n");
                    goto cleanup;
                }

                // Get the name/value mapping if the property specifies a value map.

                status = GetMapInfo(pEvent, 
                    (PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                    pInfo->DecodingSource,
                    pMapInfo);

                if (ERROR_SUCCESS != status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"GetMapInfo failed\n");
                    goto cleanup;
                }

				std::wstring prop;
                status = FormatAndPrintData(pEvent, 
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                    pData, 
                    PropertySize,
                    pMapInfo,
                    prop);

				if (bIPAddress)
				{
					char portNumberMemory[2];
					portNumberMemory[0] = *(char*)(pData+3);
					portNumberMemory[1] = *(char*)(pData+2);

					swprintf(ipAddress, L"%d.%d.%d.%d:%d", *(pData+4), *(pData+5), *(pData+6), *(pData+7), *(unsigned short*)(portNumberMemory));
					prop = std::wstring(ipAddress);
					PAINTSession::getInstance()->printAndWrite(" %d.%d.%d.%d:%d ", *(pData+4), *(pData+5), *(pData+6), *(pData+7), *(unsigned short*)(portNumberMemory));
				}
				else if (pid)
				{
					consoleMessage.PID = *(int*)pData;
					std::string processPath = getProcessPath(consoleMessage.PID, MAX_FILE_PATH_LEN, true);
					PAINTSession::getInstance()->printAndWrite(" %s ", processPath.c_str());
					consoleMessage.processPath = processPath;
					
					//On Windows PID of 4 is always the system
					if (consoleMessage.PID == 4)
						consoleMessage.processPath = "SYSTEM";
				}
				else if (numBytes)
				{
					char number[4];
					number[0] = *(char*)(pData);
					number[1] = *(char*)(pData+1);
					number[2] = *(char*)(pData+2);
					number[3] = *(char*)(pData+3);

					consoleMessage.bytes = *(int*)(number);
					//printf("NumBytes: %d\n", consoleMessage.bytes);
				}
				else if (fragment)
				{
					consoleMessage.fragment.resize(PropertySize);
					memcpy(&consoleMessage.fragment[0], pData, PropertySize);
				}
				else if (bNewTCPState)
				{
					consoleMessage.newTCPState = prop;
				}
				else if (sourceProvider)
				{
					/*
					* Taking this code out to improve performance
					*
					if (prop == L"{7D44233D-3055-4B9C-BA64-0D47CA40A232}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-WinHttp";
					else if (prop == L"{2ED6006E-4729-4609-B423-3EE7BCD678EF}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-NDIS-PacketCapture";
					else if (prop == L"{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-NDIS";
					else if (prop == L"{DD7A21E6-A651-46D4-B7C2-66543067B869}")
						consoleMessage.sourceProvider = L"NDIS Tracing";
					else if (prop == L"{EA24CD6C-D17A-4348-919009F0D5BE83DD}")
						consoleMessage.sourceProvider = L"NDIS-Capture-LightWeight-Filter";
					else if (prop == L"{E53C6823-7BB8-44BB-90DC-3F86090D48A6}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-WinSock-AFD";
					else if (prop == L"{83ED54F0-4D48-4E45-B16E-726FFD1FA4AF}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-Networking-Correlation";
					else if (prop == L"{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-TCPIP";
					else if (prop == L"{7D44233D-3055-4B9C-BA64-0D47CA40A232}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-WinHttp";
					else if (prop == L"{36C23E18-0E66-11D9-BBEB-505054503030}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-Diagnostics-Networking";
					else if (prop == L"{7DD42A49-5329-4832-8DFD-43D979153A88}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-Kernel-Network";
					else if (prop == L"{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-RPC";
					else if (prop == L"{0C478C5B-0351-41B1-8C58-4A6737DA32E3}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-WFP";
					else if (prop == L"{0BD3506A-9030-4F76-9B88-3E8FE1F7CFB6}")
						consoleMessage.sourceProvider = L"N-Wifi";
					else if (prop == L"{9580D7DD-0379-4658-9870-D5BE7D52D6DE}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-WLAN-AutoConfig";
					else if (prop == L"{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}")
						consoleMessage.sourceProvider = L"Microsoft-Windows-DHCPv6-Client";
					else if (prop == L"{E837619C-A2A8-4689-833F-47B48EBD2442}")
						consoleMessage.sourceProvider = L"BranchCacheEventProvider";

					else
						consoleMessage.sourceProvider = prop;
					*/
				}
				else if (context)
					consoleMessage.context = prop;
				else if (bTCB)
					consoleMessage.TCB = prop;

				bIPAddress = false;
				pid = false;
				numBytes = false;
				fragment = false;
				sourceProvider = false;
				context = false;
				bool bNewTCPState = false;
				bool bTCB = false;

				consoleMessage.messageParameters.push_back(prop);

                if (ERROR_SUCCESS != status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"GetMapInfo failed\n");
                    goto cleanup;
                }

                if (pData)
                {
                    free(pData);
                    pData = NULL;
                }

                if (pMapInfo)
                {
                    free(pMapInfo);
                    pMapInfo = NULL;
                }
            }
        }
    }

cleanup:

    if (pData)
    {
        free(pData);
        pData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    return status;
}


DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo, std::wstring &propertyString)
{
    UNREFERENCED_PARAMETER(pEvent);
    
    DWORD status = ERROR_SUCCESS;

    switch (InType)
    {
        case TDH_INTYPE_UNICODESTRING:
        case TDH_INTYPE_COUNTEDSTRING:
        case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
        case TDH_INTYPE_NONNULLTERMINATEDSTRING:
        {
            size_t StringLength = 0;

            if (TDH_INTYPE_COUNTEDSTRING == InType)
            {
                StringLength = *(PUSHORT)pData;
            }
            else if (TDH_INTYPE_REVERSEDCOUNTEDSTRING == InType)
            {
                StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
            }
            else if (TDH_INTYPE_NONNULLTERMINATEDSTRING == InType)
            {
                StringLength = DataSize;
            }
            else
            {
                StringLength = wcslen((LPWSTR)pData);
            }

            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%.*s", StringLength, (LPWSTR)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
            break;
        }

        case TDH_INTYPE_ANSISTRING:
        case TDH_INTYPE_COUNTEDANSISTRING:
        case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
        case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
        {
            size_t StringLength = 0;

            if (TDH_INTYPE_COUNTEDANSISTRING == InType)
            {
                StringLength = *(PUSHORT)pData;
            }
            else if (TDH_INTYPE_REVERSEDCOUNTEDANSISTRING == InType)
            {
                StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
            }
            else if (TDH_INTYPE_NONNULLTERMINATEDANSISTRING == InType)
            {
                StringLength = DataSize;
            }
            else
            {
                StringLength = strlen((LPSTR)pData);
            }

            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%.*S", StringLength, (LPSTR)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
            break;
        }

        case TDH_INTYPE_INT8:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%hd", *(PCHAR)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
            break;
        }

        case TDH_INTYPE_UINT8:
        {
            if (TDH_OUTTYPE_HEXINT8 == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PBYTE)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%hu", *(PBYTE)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }

            break;
        }

        case TDH_INTYPE_INT16:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%hd", *(PSHORT)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
            break;
        }

        case TDH_INTYPE_UINT16:
        {
            if (TDH_OUTTYPE_HEXINT16 == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PUSHORT)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else if (TDH_OUTTYPE_PORT == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%hu", ntohs(*(PUSHORT)pData)));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%hu", *(PUSHORT)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }

            break;
        }

        case TDH_INTYPE_INT32:
        {
            if (TDH_OUTTYPE_HRESULT == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PLONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%d", *(PLONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }

            break;
        }

        case TDH_INTYPE_UINT32:
        {
            if (TDH_OUTTYPE_HRESULT == OutType ||
                TDH_OUTTYPE_WIN32ERROR == OutType ||
                TDH_OUTTYPE_NTSTATUS == OutType ||
                TDH_OUTTYPE_HEXINT32 == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PULONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else if (TDH_OUTTYPE_IPV4 == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%d.%d.%d.%d", (*(PLONG)pData >>  0) & 0xff,
                                          (*(PLONG)pData >>  8) & 0xff,
                                          (*(PLONG)pData >>  16) & 0xff,
                                          (*(PLONG)pData >>  24) & 0xff));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
                if (pMapInfo)
                {
                    propertyString = PrintMapString(pMapInfo, pData);
                }
                else
                {
                    propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%lu", *(PULONG)pData));
					PAINTSession::getInstance()->wprintAndWrite(L"\n");
                }
            }

            break;
        }

        case TDH_INTYPE_INT64:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%I64d", *(PLONGLONG)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");

            break;
        }

        case TDH_INTYPE_UINT64:
        {
            if (TDH_OUTTYPE_HEXINT64 == OutType)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PULONGLONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%I64u", *(PULONGLONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }

            break;
        }

        case TDH_INTYPE_FLOAT:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%f", *(PFLOAT)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");

            break;
        }

        case TDH_INTYPE_DOUBLE:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%I64f", *(DOUBLE*)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");

            break;
        }

        case TDH_INTYPE_BOOLEAN:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%s", (0 == (PBOOL)pData) ? L"false" : L"true"));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");

            break;
        }

        case TDH_INTYPE_BINARY:
        {
            if (TDH_OUTTYPE_IPV6 == OutType)
            {
                WCHAR IPv6AddressAsString[46];
                PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

                fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
                    GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");

                if (NULL == fnRtlIpv6AddressToString)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"GetProcAddress failed with %lu.\n", status = GetLastError());
                    goto cleanup;
                }

                fnRtlIpv6AddressToString((IN6_ADDR*)pData, IPv6AddressAsString);

                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%s", IPv6AddressAsString));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
				//This is fragment data. We don't need to convert to hex-ASCII since we'll convert back to binary again
				//for writing out pcap
				/*
                for (DWORD i = 0; i < DataSize; i++)
                {
					propertyString.append(std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%.2x", pData[i])));
                }

                PAINTSession::getInstance()->wprintAndWrite(L"\n");
				*/
            }

            break;
        }

        case TDH_INTYPE_GUID:
        {
            WCHAR szGuid[50];
            
            StringFromGUID2(*(GUID*)pData, szGuid, sizeof(szGuid)-1);
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%s", szGuid));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
                
            break;
        }

        case TDH_INTYPE_POINTER:
        case TDH_INTYPE_SIZET:
        {
            if (4 == g_PointerSize)
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PULONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
            else
            {
               propertyString = std::wstring( PAINTSession::getInstance()->wprintAndWrite(L"0x%x", *(PULONGLONG)pData));
			   PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }

            break;
        }

        case TDH_INTYPE_FILETIME:
        {
            break;
        }

        case TDH_INTYPE_SYSTEMTIME:
        {
            break;
        }

        case TDH_INTYPE_SID:
        {
            WCHAR UserName[MAX_NAME];
            WCHAR DomainName[MAX_NAME];
            DWORD cchUserSize = MAX_NAME;
            DWORD cchDomainSize = MAX_NAME;
            SID_NAME_USE eNameUse;

            if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
            {
                if (ERROR_NONE_MAPPED == status)
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"Unable to locate account for the specified SID\n");
                    status = ERROR_SUCCESS;
                }
                else
                {
                    PAINTSession::getInstance()->wprintAndWrite(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                }

                goto cleanup;
            }
            else
            {
                propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%s\\%s", DomainName, UserName));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }

            break;
        }

        case TDH_INTYPE_HEXINT32:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", (PULONG)pData));
            PAINTSession::getInstance()->wprintAndWrite(L"\n");
			break;
        }

        case TDH_INTYPE_HEXINT64:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"0x%x", (PULONGLONG)pData));
            PAINTSession::getInstance()->wprintAndWrite(L"\n");
			break;
        }

        case TDH_INTYPE_UNICODECHAR:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%c", *(PWCHAR)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
            break;
        }

        case TDH_INTYPE_ANSICHAR:
        {
            propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%C", *(PCHAR)pData));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
            break;
        }

        case TDH_INTYPE_WBEMSID:
        {
            WCHAR UserName[MAX_NAME];
            WCHAR DomainName[MAX_NAME];
            DWORD cchUserSize = MAX_NAME;
            DWORD cchDomainSize = MAX_NAME;
            SID_NAME_USE eNameUse;

            if ((PULONG)pData > 0)
            {
                // A WBEM SID is actually a TOKEN_USER structure followed 
                // by the SID. The size of the TOKEN_USER structure differs 
                // depending on whether the events were generated on a 32-bit 
                // or 64-bit architecture. Also the structure is aligned
                // on an 8-byte boundary, so its size is 8 bytes on a
                // 32-bit computer and 16 bytes on a 64-bit computer.
                // Doubling the pointer size handles both cases.

                pData += g_PointerSize * 2;

                if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
                {
                    if (ERROR_NONE_MAPPED == status)
                    {
                        PAINTSession::getInstance()->wprintAndWrite(L"Unable to locate account for the specified SID\n");
                        status = ERROR_SUCCESS;
                    }
                    else
                    {
                        PAINTSession::getInstance()->wprintAndWrite(L"LookupAccountSid failed with %lu\n", status = GetLastError());
                    }

                    goto cleanup;
                }
                else
                {
                    propertyString = std::wstring(PAINTSession::getInstance()->wprintAndWrite(L"%s\\%s", DomainName, UserName));
					PAINTSession::getInstance()->wprintAndWrite(L"\n");
                }
            }

            break;
        }

    default:
        status = ERROR_NOT_FOUND;
    }

cleanup:

    return status;
}


std::wstring PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData)
{
	std::wstring toReturn;

    BOOL MatchFound = FALSE;

    if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) == EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
        (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
			toReturn.append(PAINTSession::getInstance()->wprintAndWrite(L"%s", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[*(PULONG)pData].OutputOffset)));
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if (pMapInfo->MapEntryArray[i].Value == *(PULONG)pData)
                {
                    toReturn.append(PAINTSession::getInstance()->wprintAndWrite(L"%s", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)));
					PAINTSession::getInstance()->wprintAndWrite(L"\n");
                    MatchFound = TRUE;
                    break;
                }
            }

            if (FALSE == MatchFound)
            {
                toReturn.append(PAINTSession::getInstance()->wprintAndWrite(L"%lu", *(PULONG)pData));
				PAINTSession::getInstance()->wprintAndWrite(L"\n");
            }
        }
    }
    else if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP ||
        (pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP) == EVENTMAP_INFO_FLAG_WBEM_BITMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
        (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) == EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            DWORD BitPosition = 0;

            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((*(PULONG)pData & (BitPosition = (1 << i))) == BitPosition)
                {
					toReturn.append(PAINTSession::getInstance()->wprintAndWrite(L"%s%s", 
                        (MatchFound) ? L" | " : L"", 
                        (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)));

                    MatchFound = TRUE;
                }
            }

        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((pMapInfo->MapEntryArray[i].Value & *(PULONG)pData) == pMapInfo->MapEntryArray[i].Value)
                {
                    toReturn.append(PAINTSession::getInstance()->wprintAndWrite(L"%s%s", 
                        (MatchFound) ? L" | " : L"", 
                        (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)));

                    MatchFound = TRUE;
                }
            }
        }

        if (MatchFound)
        {
            PAINTSession::getInstance()->wprintAndWrite(L"\n");
        }
        else
        {
            toReturn = PAINTSession::getInstance()->wprintAndWrite(L"%lu", *(PULONG)pData);
			PAINTSession::getInstance()->wprintAndWrite(L"\n");
        }
    }

	return toReturn;
}