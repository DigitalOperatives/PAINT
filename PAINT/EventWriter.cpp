//_____  EventWriter.cpp ___________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#include "EventWriter.h"

//Creating the static variable
EventWriter *EventWriter::m_me;

EventWriter* EventWriter::getInstance()
{
	if (m_me)
		return m_me;

	m_me = new EventWriter();

	return m_me;
}

EventWriter::EventWriter()
{
	m_currentMessageNumber = 0;
	m_isLastNDISMessageValid = false;
	m_isTCPIPOut = false;
	m_bCorrelateCorrelation = false;
}

void EventWriter::clearCorrelationActivity()
{
	m_lastCorrelActivityID = "";

	std::queue<std::string> empty;
    std::swap( m_CorrelActivityQueue, empty );

	m_isTCPIPOut = m_bCorrelateCorrelation = false;
}

void EventWriter::writeEvent(ConsoleMessage consoleMessage)
{
	//Write out the CSV file unmolested
	writeCSV(consoleMessage);

	//----------------------------------------------------------------------->
	// Large state-machine for network activity correlation
	// <----------------------------------------------------------------------
	switch (consoleMessage.eventID)
	{

	//Build up our own copy of the TCB
	case 1300: //TCP Connections exists event
	case 1051: //TCP SYN_SENT transition event
		if (consoleMessage.TCB.size() > 0)
		{
			if (consoleMessage.eventID == 1300 || !consoleMessage.newTCPState.compare(L"SynSentState"))
			{
				std::string tcbString = wstringTostringASCII(consoleMessage.TCB);
				PAINTSession::getInstance()->storePID(tcbString, consoleMessage.PID, consoleMessage.processPath);
				printf("Storing %s, %d, %s\n", tcbString.c_str(), consoleMessage.PID, consoleMessage.processPath.c_str());
			}
		}
		else
			PAINTSession::getInstance()->wprintAndWrite(L"ETW Event 1051/1300 was issued but there wasn't TCB.\n");

		clearCorrelationActivity();

		break;

	//Remove TCP sessions from the TCB if the session is no longer
	case 1193: //TCP/IP End point/connection released port
		if (consoleMessage.TCB.size() > 0)
		{
			std::string tcbString = wstringTostringASCII(consoleMessage.TCB);
			PAINTSession::getInstance()->deletePID(tcbString);
			printf("Deleting %s\n", tcbString.c_str());
		}
		else
			PAINTSession::getInstance()->wprintAndWrite(L"ETW Event 1193 was issued but there wasn't TCB.\n");

		clearCorrelationActivity();

		break;


	case 1073: //TCP Out
	case 1074: //TCP In
		//TCP-TCB correlation is unique to TCP messages.
		if (consoleMessage.TCB.size() > 0)
		{
			std::string tcbString = wstringTostringASCII(consoleMessage.TCB);
			PAINTSession::PIDName pidName = PAINTSession::getInstance()->getPID(tcbString);

			if (pidName.PID > -1)
			{
				consoleMessage.PID = pidName.PID;
				consoleMessage.processPath = pidName.processName;

				//printf("Successfully retrieved %s, %d, %s\n", tcbString.c_str(), consoleMessage.PID, consoleMessage.processPath.c_str());
			}
			else
			{
				clearCorrelationActivity();
				break;
				//printf("Failed to retrieve %s\n", tcbString.c_str());
			}
		}
		else
			PAINTSession::getInstance()->wprintAndWrite(L"ETW Event 1073/1074 was issued but there wasn't TCB.\n");
	
	//Fall through to the general TCPIP transmission handle case
	case 1169:
	case 1170:

		if (m_lastCorrelActivityID != "")
		{
			//We now map the last correlation activity ID to the PID and process name of this event
			PAINTSession::getInstance()->storeActID(m_lastCorrelActivityID, consoleMessage.PID, consoleMessage.processPath);

			if (consoleMessage.in)
			{
				while (!m_CorrelActivityQueue.empty())
				{
					std::string correlID = m_CorrelActivityQueue.front();
					m_CorrelActivityQueue.pop();
					if (correlID != "{00000000-0000-0000-0000-000000000000}")
						PAINTSession::getInstance()->storeActID(correlID, consoleMessage.PID, consoleMessage.processPath);
				}
			}
			else
			{
				m_isTCPIPOut = true;
				m_lastPIDName.PID = consoleMessage.PID;
				m_lastPIDName.processName = consoleMessage.processPath;
			}
		}

		//If this is an outbound event, we need to preserve the current correlation activity ID
		//because we will need it to correlate it with the next correlation activity ID
		//to correlate the next series of activity IDs
		if (consoleMessage.in)
			clearCorrelationActivity();
		else
		{
			std::queue<std::string> empty;
			std::swap( m_CorrelActivityQueue, empty );
		}

		break;

	case 1001: //NDIS Fragment

		// First, correlate the last NDIS fragment.
		// When a packet is going out, NDIS events seem to come in pairs. Haven't seen the case for coming in
		// but that's still possible
		if (m_isLastNDISMessageValid)
		{
			//If this is an out-going NDIS event:
			if (consoleMessage.out)
			{
				//First, flush out all stored in messages
				while (!m_NDISInMessageQueue.empty())
				{
					ConsoleMessage ndisMessage = m_NDISInMessageQueue.front();
					m_NDISInMessageQueue.pop();

					correlateNDISActivity(ndisMessage);
					if (ndisMessage.fragment.size())
						PAINTSession::getInstance()->writePacket(&ndisMessage.fragment[0], ndisMessage.fragment.size(), ndisMessage.PID, ndisMessage.processPath, ndisMessage.captureTime);
					else
						printf("There was stuff in the NDIS message queue but no fragment in that message\n");
				}

				//Now push this outbound packet into the queue
				if (consoleMessage.stackLayerString == "NDIS")
					m_NDISOutMessageQueue.push(consoleMessage);
				else
					printf("This shouldn't be happening\n");
			}
			else //If the packet is coming into NDIS, we need to wait until for the next TCPIP event
				//to see if we get a correlation
			{
				//Flush out all outbound NDIS packets, correlating them to each other as necessary
				//1. Transform the queue to a vector for easier processing
				std::vector<ConsoleMessage> messages;
				while (!m_NDISOutMessageQueue.empty())
				{
					messages.push_back(m_NDISOutMessageQueue.front());
					m_NDISOutMessageQueue.pop();
				}
				//2. If the last NDIS message's activity ID matches the current one, this and the last are the same activity
				//We will merge the two fragments so that we can output as a single packet capture
				for (int a = 0; a < messages.size(); a++)
				{
					int totalFragmentSize = messages[a].fragment.size();
					int numMatches = 0;

					for (int b = a + 1; b < messages.size(); b++)
					{
						if (messages[a].activityID != messages[b].activityID)
							break;

						totalFragmentSize += messages[b].fragment.size();
						numMatches++;
					}

					char* newFragment = (char*)malloc(totalFragmentSize);
					int copiedSize = 0;
					
					//2b. Copy the subsequent packets
					for (int c = 0; c <= numMatches; c++)
					{
						memcpy(newFragment + copiedSize, &messages[a+c].fragment[0], messages[a+c].fragment.size());
						copiedSize += messages[a+c].fragment.size();
					}

					//2c. Correlate PID
					correlateNDISActivity(messages[a]);

					//Write the packet out
					PAINTSession::getInstance()->writePacket(newFragment, totalFragmentSize, messages[a].PID, messages[a].processPath, messages[a].captureTime);

					free(newFragment);

					//Skip over to the next first packet
					a += numMatches;
				}

				//Now push this inbound packet into the queue
				if (consoleMessage.stackLayerString == "NDIS")
					m_NDISInMessageQueue.push(consoleMessage);
				else
					printf("This shouldn't be happening\n");
			}

		}
		else
		{
			m_lastNDISMessage = consoleMessage;
			m_isLastNDISMessageValid = true;
		}

		clearCorrelationActivity();

		break;

	//Networking Correlation Activity Transfer/Stop event
	case 60001:
	case 60002:
	case 60003:
		if (consoleMessage.context != L"0")
		/*
		if (consoleMessage.context == L"19" //TCP out
		 || consoleMessage.context == L"21" //TCP out
		 || consoleMessage.context == L"22" //TCP out
		 || consoleMessage.context == L"16" // TCP in
		 || consoleMessage.context == L"25" //UDP
		 || consoleMessage.context == L"27" //UDP
		 || consoleMessage.context == L"1" 
		 || consoleMessage.context == L"2" 
		 || consoleMessage.context == L"4"
		 || consoleMessage.context == L"23") //Special TCP out
		 */
		{
			if ((m_lastCorrelActivityID != ""))
			{
				if (m_bCorrelateCorrelation)
				{
					PAINTSession::getInstance()->storeActID(consoleMessage.activityID, m_lastPIDName.PID, m_lastPIDName.processName);
				}
				else
				{
					if (m_isTCPIPOut && m_lastCorrelActivityID == consoleMessage.activityID)
					{
						m_bCorrelateCorrelation = true;
					}
					else
					{
						m_CorrelActivityQueue.push(m_lastCorrelActivityID);
						m_isTCPIPOut = m_bCorrelateCorrelation = false;
					}
				}
			}
			else
				m_isTCPIPOut = m_bCorrelateCorrelation = false;
		 
			m_lastCorrelActivityID = consoleMessage.activityID;
		}

		break;

	default:
		break;
	};
}

void EventWriter::correlateNDISActivity(ConsoleMessage &consoleMessage)
{
	PAINTSession::PIDName pidName = PAINTSession::getInstance()->getActID(consoleMessage.activityID, consoleMessage.fragment.size());

	if (pidName.PID > -1)
	{
		consoleMessage.PID = pidName.PID;
		consoleMessage.processPath = pidName.processName;
		//printf("Successfully retrieved %s, %d, %s\n", consoleMesage.activityID.c_str(), consoleMesage.PID, consoleMesage.processPath.c_str());
	}
	else
	{
		consoleMessage.PID = pidName.PID;
		consoleMessage.processPath = pidName.processName;
		//printf("Failed to retrieve %s\n", consoleMesage.activityID.c_str());
	}
}

void EventWriter::writeCSV(ConsoleMessage consoleMessage)
{
	std::vector<std::wstring> tokens;
	std::wstring newMessage;
	//*
	switch (consoleMessage.eventID)
	{
	case 1300: //TCP Connections exists event
	case 1051: //TCP SYN_SENT transition event
	case 1193: //TCP/UDP/IP End point/connection released port
	case 1073: //TCP Sending data
	case 1074: //TCP Delivering data
	case 1169: //UDP Sending data
	case 1170: //UDP Delivering data
	case 1001: //NDIS fragment
		break;

	//Networking Correlation Activity Transfer/Stop event
	case 60001:
	case 60002:
	case 60003:
		if (consoleMessage.context == L"0")
			return;
		break;
		/*
		//DEBUG
		if (consoleMessage.context == L"19" //TCP out
		 || consoleMessage.context == L"21" //TCP out
		 || consoleMessage.context == L"22" //TCP out
		 || consoleMessage.context == L"16" // TCP in
		 || consoleMessage.context == L"25" //UDP
		 || consoleMessage.context == L"27" //UDP
		 || consoleMessage.context == L"1" 
		 || consoleMessage.context == L"2" 
		 || consoleMessage.context == L"4"
		 || consoleMessage.context == L"23") //Special TCP out
			break;
		else 
			return;
			*/

	default:
		return;
		break;
		
	};
	//*/
	//Event ID Column
	PAINTSession::getInstance()->CSVPrintAndWrite("\"Event %d\"", m_currentMessageNumber++);

	//Stack Layer
	PAINTSession::getInstance()->CSVPrintAndWrite(",\"%s\"", consoleMessage.stackLayerString.c_str());

	//PID and Process Path/Name
	PAINTSession::getInstance()->CSVPrintAndWrite(",\"%d\",\"%s\"", consoleMessage.PID, consoleMessage.processPath.c_str());

	//Activity ID
	PAINTSession::getInstance()->CSVPrintAndWrite(",\"%s\"", consoleMessage.activityID.c_str());

	//Event ID
	PAINTSession::getInstance()->CSVWPrintAndWrite(L",\"%d\"", consoleMessage.eventID);

	//Number of bytes involved
	PAINTSession::getInstance()->CSVPrintAndWrite(",\"%d\"", consoleMessage.bytes);

	//Whether it's inbound or outbound traffic
	if (consoleMessage.in)
	{
		PAINTSession::getInstance()->CSVPrintAndWrite(",\"IN\"");
	}
	else
	{
		PAINTSession::getInstance()->CSVPrintAndWrite(",\"\"");
	}
	if (consoleMessage.out)
	{
		PAINTSession::getInstance()->CSVPrintAndWrite(",\"OUT\"");
	}
	else
	{
		PAINTSession::getInstance()->CSVPrintAndWrite(",\"\"");
	}

	//Source Provider
	PAINTSession::getInstance()->CSVWPrintAndWrite(L",\"%s\"", consoleMessage.sourceProvider.c_str());

	//Context
	PAINTSession::getInstance()->CSVWPrintAndWrite(L",\"%s\"", consoleMessage.context.c_str());

	//Event message
	tokens = split(consoleMessage.message, L'%');
	if (tokens.size() > 1)
	{
		//The first token has no parameter numbers
		newMessage.append(tokens[0]);

		for (int a = 1; a < tokens.size(); a++)
		{
			int number = 0;
			int numberOfDigits = 0;
			
			//We need to convert the string to a number. We're going to assume two-digits most
			//Which should be a very safe assumption
			if (isADigitWChar(tokens[a][1]))
			{
				numberOfDigits = 2;
				number = _wtoi(tokens[a].substr(0, 2).c_str());
			}
			else
			{
				numberOfDigits = 1;
				number = _wtoi(tokens[a].substr(0, 1).c_str());
			}

			newMessage.append(consoleMessage.messageParameters[number-1]);
			newMessage.append(tokens[a].substr(numberOfDigits, tokens[a].size()-numberOfDigits));

			//PAINTSession::getInstance()->wprintAndWrite(L"Token: %s\n", tokens[a].c_str());
		}
	}
	else
		newMessage.append(consoleMessage.message);

	PAINTSession::getInstance()->CSVWPrintAndWrite(L",\"%s\"", newMessage.c_str());

	//Fragment if available
	/*
	if (consoleMessage.fragment.size() > 0)
	{
		PAINTSession::getInstance()->CSVPrintAndWrite(",\"%s\"", consoleMessage.md5Text);
		PAINTSession::getInstance()->CSVWPrintAndWrite(L",\"%s\"", consoleMessage.fragment.c_str());
	}
	else
	*/
	{
		PAINTSession::getInstance()->CSVPrintAndWrite(",\"\",\"\"");
	}

	//Parameters
	//Need to see these only when debugging
	//for (int a = 0; a < consoleMessage.messageParameters.size(); a++)
	//{
	//	wprintf(L", %%%d=%s", a+1, consoleMessage.messageParameters[a].c_str());
	//	fwprintf(outputCSVFile, L", %%%d=%s", a+1, consoleMessage.messageParameters[a].c_str());
	//}

	PAINTSession::getInstance()->CSVWPrintAndWrite(L"\n");
}