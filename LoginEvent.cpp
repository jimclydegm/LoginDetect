// LoginEvent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

#include <windows.h>
//#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include <conio.h>
#include <atlpath.h>
#include <atlcoll.h>

#pragma comment(lib, "wevtapi.lib")

const int SIZE_DATA = 4096;
TCHAR XMLDataCurrent[SIZE_DATA];
TCHAR XMLDataUser[SIZE_DATA];

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

DWORD PrintEvent(EVT_HANDLE hEvent); // Shown in the Rendering Events topic
DWORD PrintEvent(UINT16 *eventID); 
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);

// The structured XML query.
// event 4625 is FAIL
// event 4624 is PASS
#define QUERY \
    L"<QueryList>" \
    L"  <Query Path='Security'>" \
    L"    <Select>Event/System[EventID=4625]</Select>" \
    L"    <Select>Event/System[EventID=4624]</Select>" \
    L"  </Query>" \
    L"</QueryList>"

int main()
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hResults = NULL;
	LPWSTR pwsPath = (LPWSTR)L"Security";
	//LPWSTR pwsQuery = (LPWSTR)L"Event/System[EventID=4625,4624]";

	hResults = EvtQuery(NULL, NULL, QUERY, EvtQueryChannelPath );// EvtQueryReverseDirection);
	hResults = EvtSubscribe(NULL, NULL, pwsPath, QUERY, NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeToFutureEvents);
	if (NULL == hResults)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			wprintf(L"The channel was not found.\n");
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call the EvtGetExtendedStatus function to try to get 
			// additional information as to what is wrong with the query.
			wprintf(L"The query is not valid.\n");
		else
			wprintf(L"EvtQuery failed with %lu.\n", status);

		goto cleanup;
	}
	Sleep(10000);

cleanup:

	if (hResults)
		EvtClose(hResults);
}

DWORD GetEventValues(EVT_HANDLE hEvent, UINT16 *eventID, UINT16 *logonType)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hContext = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	LPCTSTR ppValues[] = { _T("Event/System/EventID"), _T("Event/EventData/Data[@Name=\"LogonType\"]") };
	DWORD count = sizeof(ppValues) / sizeof(LPWSTR);

	hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	if (NULL == hContext)
	{
		// EvtCreateRenderContext failed 
		goto cleanup;
	}

	if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
			if (pRenderedValues)
			{
				EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				// malloc failed
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			// EvtRender failed
			goto cleanup;
		}
	}

	*eventID = pRenderedValues[0].UInt16Val;
	*logonType = pRenderedValues[1].UInt16Val;

cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}

// The callback that receives the events that match the query criteria. 
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
	UNREFERENCED_PARAMETER(pContext);

	DWORD status = ERROR_SUCCESS;
	UINT16 eventID = NULL, logonType = NULL;

	status = GetEventValues(hEvent, &eventID, &logonType);

	if (status != ERROR_SUCCESS)
		return status;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			wprintf(L"The subscription callback was notified that event records are missing.\n");
			// Handle if this is an issue for your application.
		}
		else
		{
			wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
		}
		break;

	case EvtSubscribeActionDeliver:

		// if you want to print the xml content
		//if (ERROR_SUCCESS != (status = PrintEvent(hEvent)))
		//{
		//	// time to write to registry
		//	goto cleanup;
		//}
		
		// if you want to print event info
		if (ERROR_SUCCESS != (status = PrintEvent(&eventID)))
		{
			goto cleanup;
		}

		break;

	default:
		wprintf(L"SubscriptionCallback: Unknown action.\n");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}


DWORD PrintEvent(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			if (pRenderedContent)
			{
				EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", status);
			goto cleanup;
		}
	}

	ZeroMemory(XMLDataCurrent, SIZE_DATA);
	lstrcpyW(XMLDataCurrent, pRenderedContent);

	wprintf(L"EvtRender data %s\n", XMLDataCurrent);

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

DWORD PrintEvent(UINT16 *eventID)
{
	DWORD status = ERROR_SUCCESS;

	// event 4625 is FAIL
	// event 4624 is PASS
	
	if (*eventID == 4625)
		wprintf(L"User login FAIL\n");
	else if(*eventID == 4624)
		wprintf(L"User login PASS\n");
	else
		wprintf(L"User login UNKNOWN\n");
	
	return status;
}