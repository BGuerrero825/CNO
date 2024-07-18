//---------------------------------------------------------------------------------------------------------------------
//  EventLogAccess.c
//
//  Utilities for programmatically accessing Windows eventlogs files
//---------------------------------------------------------------------------------------------------------------------
#include "EventlogAccess.h"
#include "WindowsQueries.h"
#include <stdio.h>
#include <TlHelp32.h>
#include <windows.h>

//
// START: //////////////////////////// IMPLEMENT LAB3 utility code HERE ////////////////////////////
//      Add Event log access specific utilities here
//

unsigned FindProcessWithModule(const wchar_t * processName, const wchar_t * moduleName)
{
	HANDLE processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (processList == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to create snapshot of current processes. Error: %u\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32W currProcess = { 0, .dwSize = sizeof(PROCESSENTRY32W)};
	if (!Process32First(processList, &currProcess))
	{
		fprintf(stderr, "Failed to retrieve first process from process list. Error: %u\n", GetLastError());
		CloseHandle(processList);
		return 0;
	}

	// iterate through the list of processes until desired process found or end of processes reached
	unsigned retval = 0;
	do
	{
		// check if name of process matches given name
		if (!wcscmp(currProcess.szExeFile, processName))
		{
			// check if process contains given module
			if (FindLoadedModule(currProcess.th32ProcessID, moduleName))
			{
				CloseHandle(processList);
				return currProcess.th32ProcessID;
			}
		}

		// if getting the next process returns an error
		retval = Process32NextW(processList, &currProcess);
		if (!retval)
		{
			if (GetLastError() == ERROR_NO_MORE_FILES)
			{
				fprintf(stderr, "Reached the end of available processes. ");
			}
			fprintf(stderr, "Failed to retrieve next process from process list. Error: %u\n", GetLastError());
			CloseHandle(processList);
			return 0;
		}

	} while (retval);

	CloseHandle(processList);
	return 0;
}


bool FindLoadedModule(unsigned processPID, const wchar_t* moduleName)
{
	HANDLE moduleList = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processPID);
	if (moduleList == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to create snapshot of loaded modules. Error: %u\n", GetLastError());
		return false;
	}

	MODULEENTRY32W currModule = { 0, .dwSize = sizeof(MODULEENTRY32W) };
	if (!Module32FirstW(moduleList, &currModule))
	{
		fprintf(stderr, "Failed to retrieve first module from module list. Error: %u\n", GetLastError());
		CloseHandle(moduleList);
		return false;
	}

	// iterate through the list of modules until desired module found or end of modules reached
	unsigned retval = 0;
	do
	{
		// check if name of module matches given name
		if (!wcscmp(currModule.szModule, moduleName))
		{
			CloseHandle(moduleList);
			return true;
		}

		// if getting the next module returns an error
		retval = Module32NextW(moduleList, &currModule);
		if (!retval)
		{
			//fprintf(stderr, "Failed to retrieve next module from module list. Error: %u\n", GetLastError());
			CloseHandle(moduleList);
			return false;
		}

	} while (retval);

	CloseHandle(moduleList);
	return false;

}

HANDLE DuplicateHandleFromProcess(HANDLE processHandle, HANDLE desiredHandle)
{
	HANDLE duplicatedHandle = NULL;
	if (!DuplicateHandle(processHandle, desiredHandle, GetCurrentProcess(), &duplicatedHandle, 0, true, DUPLICATE_SAME_ACCESS))
	{
		return NULL;
	}
	return duplicatedHandle;
}


static unsigned GetFileObjectTypeIndex()
{
	// create a dummy file in current process
    HANDLE dummyFile = CreateFileA("NUL", GENERIC_READ, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );
	unsigned valDummyFile = (unsigned) (uintptr_t) dummyFile;
	if (dummyFile == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to create a dummy file \"NUL\". Error: %u\n", GetLastError());
		return 0;
	}
	// create a snapshot of all system handles
    PSYSTEM_HANDLE_INFORMATION handlesInfo = GetSystemHandleInformation();
	CloseHandle(dummyFile);	// no longer needed after snapshot is taken
	if (!handlesInfo)
	{
		fprintf(stderr, "Failed to get handle information from the system.\n");
		return 0;
	}

	// search system handles for the dummy file handle, then retrieve its ObjectTypeIndex
	unsigned currentPID = GetCurrentProcessId();
    for (unsigned idx = 0; idx < handlesInfo->NumberOfHandles; idx++)
	{
        if (handlesInfo->Handles[idx].UniqueProcessId == currentPID && handlesInfo->Handles[idx].HandleValue == valDummyFile)
		{
			unsigned fileObjectTypeIndex = handlesInfo->Handles[idx].ObjectTypeIndex;
			HeapFree(GetProcessHeap(), 0, handlesInfo);
			return fileObjectTypeIndex;
        }
    }

	fprintf(stderr, "Could not find the file handle within current process.\n");
	HeapFree(GetProcessHeap(), 0, handlesInfo);
	return 0;
}


HANDLE FindFileHandleByName(unsigned fileProcessPID, const wchar_t * requestedFileName)
{

	unsigned fileObjectTypeIndex = GetFileObjectTypeIndex();

    PSYSTEM_HANDLE_INFORMATION handlesInfo = GetSystemHandleInformation();
	if (!handlesInfo)
	{
		fprintf(stderr, "Failed to get handle information from the system.\n");
		return 0;
	}

	HANDLE fileProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, true, fileProcessPID);
	if (!fileProcessHandle)
	{
		fprintf(stderr, "Failed to open a process handle with duplication permissions for process PID: %lu. Error %u.\n", fileProcessPID, GetLastError());
		HeapFree(GetProcessHeap(), 0, handlesInfo);
		return NULL;
	}

	// for each handle, duplicate handle, get its file name, then compare the name to the requested file name
    for (size_t idx = 0; idx < handlesInfo->NumberOfHandles; idx++)
	{
		// skip this iteration if the PID and object type index dont match
		if (handlesInfo->Handles[idx].UniqueProcessId != fileProcessPID || handlesInfo->Handles[idx].ObjectTypeIndex != fileObjectTypeIndex)
		{
			continue;
		}

		// duplicate the handle to the current process so it can be queried
		HANDLE duplicatedHandle = DuplicateHandleFromProcess(fileProcessHandle, (HANDLE) (uintptr_t) handlesInfo->Handles[idx].HandleValue);
		if (!duplicatedHandle)
		{
			fprintf(stderr, "Failed to duplicate file handle from process PID: %u. Error %u.\n", fileProcessPID, GetLastError());
			continue;
			//CloseHandle(fileProcessHandle);
			//HeapFree(GetProcessHeap(), 0, handlesInfo);
			//return NULL;
		}
		// get file name from the file handle
		wchar_t handleFileName[1024] = { 0 };
		if (!GetFileNameFromHandle(duplicatedHandle, handleFileName, sizeof(handleFileName)))
		{
			//fprintf(stderr, "The given handle's file name could not be retrieved using NtQueryInformationFile().\n");
			CloseHandle(duplicatedHandle);
			continue;
		}

		// return the duplicated handle if the file name matches the requested name
		if (!wcscmp(handleFileName, requestedFileName))
		{
			//printf("String matched! Found: \"%ls\"\n", handleFileName);
			printf("Event Log Name: \"%ls\"\n\n", handleFileName);
			HeapFree(GetProcessHeap(), 0, handlesInfo);
			CloseHandle(fileProcessHandle);
			return duplicatedHandle;
		}
		CloseHandle(duplicatedHandle);
    }

	fprintf(stderr, "No file handles names matched the name given: \"%ls\"\n", requestedFileName);

    HeapFree(GetProcessHeap(), 0, handlesInfo);
	CloseHandle(fileProcessHandle);
	return NULL;
}


bool DumpEvtxFileHeader(HANDLE fileHandle)
{
	// create file mapping
	HANDLE mapHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, EVTX_FILE_HEADER_SIZE, "EvtxFileHeaderMapping");
	if (mapHandle == NULL)
	{
		fprintf(stderr, "Failed to create file mapping. Error: %ld.\n", GetLastError());
		return false;
	}

	// map view into the file
	PEVTX_FILE_HEADER pFileHeader = (PEVTX_FILE_HEADER) MapViewOfFile(mapHandle, FILE_READ_ACCESS, 0, 0, 0);
	if (pFileHeader == NULL)
	{
		fprintf(stderr, "Failed to map a view of the file. Error: %ld.\n", GetLastError());
		CloseHandle(mapHandle);
		return false;
	}

	// check file signature to ensure it is an evtx
	if (strncmp((char *) pFileHeader->Signature, EVTX_FILE_HDR_SIGNATURE, EVTX_FILE_HDR_SIGNATURE_SIZE)) {
		fprintf(stderr, "File is not a Event Log (evtx) file.\n");
	}

	// print out structure fields
	printf("--- Event Log File Header --- \n");
	printf("Signature: ");
	for (int idx = 0; idx < EVTX_FILE_HDR_SIGNATURE_SIZE; idx++)
	{
		printf("%02X ", pFileHeader->Signature[idx]);
	}
	printf(" \"%s\"", pFileHeader->Signature);
	printf("\n");
	printf("First Chunk Header: %llu\n", pFileHeader->FirstChunkNumber);
	printf("Last Chunk Header: %llu\n", pFileHeader->LastChunkNumber);
	printf("Next Record Id: %llu\n", pFileHeader->NextRecordId);
	printf("Header Size: %lu\n", pFileHeader->HeaderSize);
	printf("Minor Version: %u\n", pFileHeader->MinorVersion);
	printf("Major Version: %u\n", pFileHeader->MajorVersion);
	printf("First Chunk Offset: %u\n", pFileHeader->FirstChunkOffset);
	printf("Number Of Chunks: %u\n", pFileHeader->NumberOfChunks);
	printf("Flags: %u\n", pFileHeader->Flags);
	printf("Checksum: %08X\n\n", pFileHeader->Checksum);

	CloseHandle(mapHandle);
	UnmapViewOfFile(pFileHeader);
	return true;
}


bool DumpEvtxFirstChunkHeader(HANDLE fileHandle)
{
	// create file mapping
	HANDLE mapHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, EVTX_FILE_FIRST_CHUNK_OFFSET + sizeof(EVTX_FILE_HEADER), "EvtxChunkHeaderMapping");
	if (mapHandle == NULL)
	{
		fprintf(stderr, "Failed to create file mapping. Error: %ld.\n", GetLastError());
		return false;
	}

	// map view into the file
	PEVTX_CHUNK_HEADER pChunkHeader = (PEVTX_CHUNK_HEADER)MapViewOfFile(mapHandle, FILE_READ_ACCESS, 0, 0, 0);
	if (pChunkHeader == NULL)
	{
		fprintf(stderr, "Failed to map a view of the file. Error: %ld.\n", GetLastError());
		CloseHandle(mapHandle);
		return false;
	}

	// increment pointer to start of first chunk offset
	pChunkHeader = (PEVTX_CHUNK_HEADER) ((uint8_t *) pChunkHeader + EVTX_FILE_FIRST_CHUNK_OFFSET);


	// check chunk signature to ensure it is an evtx
	if (strncmp((char *) pChunkHeader->Signature, EVTX_CHUNK_HDR_SIGNATURE, EVTX_CHUNK_HDR_SIGNATURE_SIZE)) {
		fprintf(stderr, "File is not a Event Log (evtx) file.\n");
	}

	// print out structure fields
	printf("--- Event Log First Chunk Header --- \n");
	printf("Signature: ");
	for (int idx = 0; idx < EVTX_FILE_HDR_SIGNATURE_SIZE; idx++)
	{
		printf("%02X ", pChunkHeader->Signature[idx]);
	}
	printf(" \"%s\"", pChunkHeader->Signature);
	printf("\n");
	printf("First Event Record Number: %llu\n", pChunkHeader->FirstEventRecordNumber);
	printf("Last Event Record Number: %llu\n", pChunkHeader->LastEventRecordNumber);
	printf("First Event Record ID: %llu\n", pChunkHeader->FirstEventRecordId);
	printf("Last Event Record ID: %llu\n", pChunkHeader->LastEventRecordId);
	printf("Pointer Data Offset: %lu\n", pChunkHeader->PointerDataOffset);
	printf("Last Event Record Offset: %lu\n", pChunkHeader->LastEventRecordOffset);
	printf("Free Space Offset: %lu\n", pChunkHeader->FreeSpaceOffset);
	printf("Event Records Checksum: %08X\n", pChunkHeader->EventRecordsChecksum);
	printf("In Use Flag: %lu\n", pChunkHeader->InUseFlag);
	printf("Checksum: %08X\n\n", pChunkHeader->Checksum);


	CloseHandle(mapHandle);
	UnmapViewOfFile(pChunkHeader);
	return true;
}
