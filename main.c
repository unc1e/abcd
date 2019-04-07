/*#include "ntdll.h"


HANDLE WrOpenThread (
	OUT DWORD *status,
	IN DWORD dwDesiredAccess,
	IN DWORD dwThreadId
	)

/*
Routine description:

	This routine opens a thread.

Arguments:

	status - A pointer to a variable that receives the NTSTATUS.

	dwDesiredAccess - Thread access right.

	dwThreadId - Identifier of the thread.

Return value:
	
	If the routine succeeds the return value is an open handle to the specified thread.

	If the routine fails the return value is NULL. You should check the 'status' variable.

*/
{
	OBJECT_ATTRIBUTES ObjAttr;
	CLIENT_ID ClientId;
	HANDLE hThread = 0;

	// Preparing args (look disasm kernelbase.dll).

	RtlZeroMemory(&ObjAttr, sizeof(ObjAttr));
	ObjAttr.Length = sizeof(ObjAttr);

	ClientId.UniqueProcess = 0;
	ClientId.UniqueThread = (HANDLE)dwThreadId;

	// Will we be lucky? ;p

	*status = NtOpenThread(&hThread, dwDesiredAccess, &ObjAttr, &ClientId);
	return hThread;
}

/*********************************************************************************/

DWORD WrSystemExtendedProcessInformation (
	OUT DWORD *status,
	OUT SYSTEM_PROCESS_INFORMATION **ppspi
	)

/*
Routine description:

	This routine allocates memory and gets SYSTEM_PROCESS_INFORMATION structure.

Arguments:

	status - A pointer to a variable that receives the NTSTATUS.

	ppspi - A pointer to a pointer that recieves address of the SYSTEM_PROCESS_INFORMATION structure.

Return value:
	
	If the routine succeeds the return value is NULL.

	If the routine fails the return value is negative. You should check the 'status' variable.

Remarks:

	Don't forget to free up memory region after use.

*/
{
	DWORD nSize;

	// Get struct size.

	*status = NtQuerySystemInformation(SystemExtendedProcessInformation, *ppspi, 0, &nSize);
	if (*status != STATUS_INFO_LENGTH_MISMATCH)
		return -1;

	// Allocate region.

	*status = NtAllocateVirtualMemory(NtCurrentProcess, ppspi, 0, &nSize, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(*status))
		return -2;

	// Fill struct.

	*status = NtQuerySystemInformation(SystemExtendedProcessInformation, *ppspi, nSize, &nSize);
	if (!NT_SUCCESS(*status))
		return -3;

	return 0;
}

/*********************************************************************************/


DWORD WINAPI thread()
{

	PSYSTEM_PROCESS_INFORMATION pspi = 0;
	DWORD dwPid;
	DWORD status;

	// The pointer may be invalid.

	__try
	{
		dwPid = *(DWORD *)(__readfsdword(0x18) + 0x20); // Is not cross-platform
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		#ifdef _DEBUG
			printf("teb");
			_getch();
		#endif

		NtTerminateProcess(-1, 0); // Add an error handler here.
	}
	
	WrSystemExtendedProcessInformation(&status, &pspi);
	if (!NT_SUCCESS(status))
	{
		#ifdef _DEBUG
			printf("WrSystemExtendedProcessInformation: %X", status);
			_getch();
		#endif

		NtTerminateProcess(-1, 0); // Add an error handler here
	}
	
	while (pspi->NextEntryOffset && pspi->UniqueProcessId != dwPid)		
		pspi = (DWORD)pspi + pspi->NextEntryOffset;

	// Lol, may be some driver? or our teb was modifided.

	if (pspi->UniqueProcessId != dwPid)
	{
		#ifdef _DEBUG
			printf("can't find process");
			_getch();
		#endif

		NtTerminateProcess(-1, 0); // Add an error handler here.
	}

	#ifdef _DEBUG
		printf("------------\n%d - > %ls\n", pspi->UniqueProcessId, pspi->ImageName.Buffer);
		printf("threads: %d handles: %d\n", pspi->NumberOfThreads, pspi->HandleCount);
		printf("parent id %d\n---------\n", pspi->InheritedFromUniqueProcessId); // Maybe we're under a loader.
	#endif

	for (unsigned int i = 0; i < pspi->NumberOfThreads; i++)
	{
		HANDLE hThread = WrOpenThread(&status, THREAD_ALL_ACCESS, pspi->Threads[i].ThreadInfo.ClientId.UniqueThread);
		if (!NT_SUCCESS(status))
		{
			#ifdef _DEBUG
				printf("WrOpenThread: %X", status);
				_getch();
			#endif

			NtTerminateProcess(-1, 0); // Add an error handler here.
		}

		status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &pspi->Threads[i].Win32StartAddress, 4, 0);
		if (!NT_SUCCESS(status))
		{
			#ifdef _DEBUG
				printf("NtQueryInformationThread: %X", status);
				_getch();
			#endif

			NtTerminateProcess(-1, 0); // Add an error handler here.
		}

		#ifdef _DEBUG
			printf("thread id %d\n", pspi->Threads[i].ThreadInfo.ClientId.UniqueThread);
			printf("priority %X time %I64d\n", pspi->Threads[i].ThreadInfo.Priority, pspi->Threads[i].ThreadInfo.CreateTime.QuadPart);
			printf("start addr %X\n", pspi->Threads[i].Win32StartAddress);
		#endif

		status = NtClose(hThread);
		if (!NT_SUCCESS(status))
		{
			#ifdef _DEBUG
				printf("NtClose: %X", status);
				_getch();
			#endif

			NtTerminateProcess(-1, 0); // Add an error handler here.
		}

		__try
		{
			PEXCEPTION_REGISTRATION_RECORD pExceptionRecord = **(DWORD **)pspi->Threads[i].TebAddress;
			while (pExceptionRecord != 0xFFFFFFFF)
			{
				#ifdef _DEBUG
					printf("SEH handler: %X\n", pExceptionRecord->Handler);
				#endif

				pExceptionRecord = pExceptionRecord->Next;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#ifdef _DEBUG
				printf("seh chain");
				_getch();
			#endif

			NtTerminateProcess(-1, 0); // Add an error handler here.
		}
		
		#ifdef _DEBUG
			printf("\n");
		#endif
	}

	_getch();
	return 0;
}*/