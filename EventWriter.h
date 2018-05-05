//_____  EventWriter.h _____________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#ifndef EVENT_WRITER_H
#define EVENT_WRITER_H

#include "PAINTSession.h"
#include "PAINT.h"
#include <queue>

class EventWriter
{
public:

	static EventWriter* getInstance();
	void writeEvent(ConsoleMessage consoleMessage);
	
private:
	EventWriter();
	~EventWriter();

	void writeCSV(ConsoleMessage consoleMesage);
	void correlateNDISActivity(ConsoleMessage &consoleMesage);

	void clearCorrelationActivity();

	static EventWriter *m_me;
	int m_currentMessageNumber;

	ConsoleMessage m_lastNDISMessage;
	bool m_isLastNDISMessageValid;

	bool m_isTCPIPOut;
	bool m_bCorrelateCorrelation;
	PAINTSession::PIDName m_lastPIDName;

	std::string m_lastCorrelActivityID;
	std::queue<std::string> m_CorrelActivityQueue;

	std::queue<ConsoleMessage> m_NDISInMessageQueue;
	std::queue<ConsoleMessage> m_NDISOutMessageQueue;
};

#endif