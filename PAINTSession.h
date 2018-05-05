//_____  PAINTSession.h ____________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#ifndef PAINT_SESSION_H
#define PAINT_SESSION_H

#include <hash_map>
#include "Pcap.h"

class PAINTSession
{
public:

	struct PIDName
	{
		int PID;
		std::string processName;
	};

	static PAINTSession* getInstance();

	void storePID(std::string TCB, int PID, std::string processName);
	void deletePID(std::string TCB);
	PIDName getPID(std::string TCB);

	void storeActID(std::string actID, int PID, std::string processName);
	void deleteActID(std::string actID);
	void emptyActIDMap();
	PIDName getActID(std::string actID, int packetSize);

	int printAndWrite(const char* format, ... );
	WCHAR* wprintAndWrite(const wchar_t* format, ... );

	int CSVPrintAndWrite(const char* format, ... );
	WCHAR* CSVWPrintAndWrite(const wchar_t* format, ... );

	void writePacket(char* fragment, int size, int PID, std::string processName, unsigned long long currentTimeMicroSeconds);
	
private:
	PAINTSession();
	~PAINTSession();

	static PAINTSession *m_me;

	size_t m_formattedStringLen;
	WCHAR *m_formattedString;

	FILE *m_outputCSVFile;
	FILE *m_consoleOutputFile;
	Pcap m_pcapFile;

	std::hash_map<std::string, PIDName> m_TCBToPIDName;
	std::hash_map<std::string, PIDName> m_ActIDToPIDName;
};

#endif