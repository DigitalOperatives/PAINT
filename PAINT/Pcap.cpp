//_____  Pcap.cpp __________________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#include "Pcap.h"
#include "WiresharkPipe.h"

unsigned long long Pcap::startTime;
FILE *Pcap::pcapFile;
FILE *Pcap::processFile;
unsigned int Pcap::numPacketsToFlush;
bool Pcap::bForceWireless;

Pcap::Pcap()
{
	pcapFile = 0;
	packetNumber = 0;
	numPacketsToFlush = 0;
}

Pcap::~Pcap()
{
	fclose(pcapFile);
	fclose(processFile);
}

int Pcap::open(const char* fileName)
{
	pcapFile = _fsopen(fileName, "wb", _SH_DENYNO);
	if(pcapFile == 0)
	{
		printf("Error: the file '%s' was not opened.\n", fileName);
		return -1;
	}

	std::string processFileName(fileName);
	processFileName.append(".process");

	processFile = _fsopen(processFileName.c_str(), "wb", _SH_DENYNO);
	if(processFile == 0)
	{
		printf("Error: the file '%s' was not opened.\n", processFileName.c_str());
	}
	
	PCAPHeader h;
	h.magicNumber = 0xa1b2c3d4; //Magic number
	h.majorVersion = 2;		//Major version
    h.minorVersion = 4;		//Minor version
    h.timeZone = 0;			//Time zone
    h.accuracy = 0;			//Time stamp accuracy
    h.maxLength = MAX_CAPTURE_SIZE;		//Max length of captured packets, in octets
	h.dataLinkType = 1;

	fwrite(&h, 1, sizeof(PCAPHeader), pcapFile);
	fflush(pcapFile);

    startTime = getCurrentTimeInMicroSeconds();

	return 0;
}

unsigned long long Pcap::getCurrentTimeInMicroSeconds()
{
	FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned long long tt = ft.dwHighDateTime;
    tt <<=32;
    tt |= ft.dwLowDateTime;
    tt /=10;

	return tt;
}

//DEBUG
//#include "PAINTSession.h" 

void Pcap::writePacket(int length, char* data, int PID, std::string processName, unsigned long long currentTimeMicroSeconds)
{
	if (!pcapFile)
		return;

	int subt = 0;

	packetNumber++;

	//DEBUG
	//PAINTSession::getInstance()->CSVPrintAndWrite("Packet %d, %d, bytes, %d, %s\n", packetNumber, length, PID, processName.c_str());

	//If this is wireless data, we need to build up the fake Ethernet header
	//like how the driver does
	if (bForceWireless)
	{
		_802_11_Header *header = (_802_11_Header *)data;

		/*
		//DEBUG
		printf("----------------------------------------   %d\n", length);
		printf("Protocol Version: %X\n", header->ver_type_subtype & 0x03);
		printf("Type: %X\n", header->ver_type_subtype>>2 & 0x03);
		printf("Sub Type: %X\n", header->ver_type_subtype>>4 & 0x0F);
		printf("Add1: %X:%X:%X:%X:%X:%X\n", header->Add1[0], header->Add1[1], header->Add1[2], header->Add1[3], header->Add1[4], header->Add1[5]);
		printf("Add2: %X:%X:%X:%X:%X:%X\n\n", header->Add2[0], header->Add2[1], header->Add2[2], header->Add2[3], header->Add2[4], header->Add2[5]);
		*/

		//Note that the bits in the ver_type_subtype byte are reversed in order
		if ( header->ver_type_subtype == 0x88) //Data Frame
			subt = 20;
		else if ( header->ver_type_subtype == 0x08) //QoS Data Frames don't have 2-byte QoS field
			subt = 18;

		//Copy over the ethernet-equivalent destination and source MAC
		memcpy(data+subt, data + 4, 12);
	}
	//<<<---------------------------------------------------------------------------------

	//Get the current time in seconds and microseconds
	PCAPRecordHeader h;
	currentTimeMicroSeconds -= startTime;
	h.timeStampSecs = currentTimeMicroSeconds / 1000000;
	h.timeStampMicroSecs = currentTimeMicroSeconds % 1000000;

	//Enforce max capture size
	if (length > MAX_CAPTURE_SIZE)
		h.includeLength = MAX_CAPTURE_SIZE;
	else
		h.includeLength = length - subt;

	h.actualLength = length - subt;

	//Write out the pcap file
	fwrite(&h, 1, sizeof(PCAPRecordHeader), pcapFile);
	fwrite(data + subt, 1, h.includeLength, pcapFile);

	if (!processFile)
		return;

	//Write out the process file
	int processNameLength = processName.size();
	fwrite((void*)&packetNumber, sizeof(int), 1, processFile);
	fwrite((void*)&PID, sizeof(int), 1, processFile);
	fwrite((void*)&processNameLength, sizeof(int), 1, processFile);
	if (processNameLength > 0)
		fwrite((void*)processName.c_str(), sizeof(char), processNameLength, processFile);

	numPacketsToFlush++;
}

void Pcap::flushPacket()
{
	char temp[512];

	//Now notify Wireshark that there's new data via pipe
	if (numPacketsToFlush > 0)
	{
		fflush(pcapFile);
		fflush(processFile);
		writeWireshark(2, 'P', itoa(numPacketsToFlush, temp, 10));
		numPacketsToFlush = 0;
	}
}