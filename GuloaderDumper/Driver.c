#define NDIS_WDM = 1 
#define NDIS630 = 1

#include <wchar.h>

#include <ntifs.h>
#include <ntimage.h>
#include <fwpsk.h>     
#include <fwpmk.h>
#include <fltKernel.h> 
#include <fwpmu.h>
#include <initguid.h>

//Define some constants here

UINT64 g_filterId = 0;

#define IOCTL_SEND_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


// {3450142C-9F2D-49A7-A830-9344847DB98A}
DEFINE_GUID(SUB_LAYER_GUID ,
    0x3450142c, 0x9f2d, 0x49a7, 0xa8, 0x30, 0x93, 0x44, 0x84, 0x7d, 0xb9, 0x8a);


// {AEB33419-1D3C-466E-A0DC-C875E3308025}
DEFINE_GUID(YOUR_CALLOUT_GUID ,
    0xaeb33419, 0x1d3c, 0x466e, 0xa0, 0xdc, 0xc8, 0x75, 0xe3, 0x30, 0x80, 0x25);

// {F8451FE0-00E8-4C6A-BB42-6CE75DC4AA58}
DEFINE_GUID(DUMPER_DEVICE_GUID ,
    0xf8451fe0, 0xe8, 0x4c6a, 0xbb, 0x42, 0x6c, 0xe7, 0x5d, 0xc4, 0xaa, 0x58);



NTKERNELAPI PVOID PsGetProcessWow64Process(__in PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Process);

HANDLE targetProcess = 0;
LONG amtProcesses = 0;
HANDLE currentProcess = 0;
HANDLE logFileHandle = NULL;
HANDLE g_EngineHandle = NULL;

UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\TestDevice"); 

UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\TestDevice");

UINT32 calloutId = 0;
UINT32 addCalloutId = 0;

PDEVICE_OBJECT g_DeviceObject = NULL;

UNICODE_STRING PidFilePath = RTL_CONSTANT_STRING(L"C:\\target_pid");

UNICODE_STRING OutputFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\output.bin");

UNICODE_STRING LogFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\logfile.txt");

UNICODE_STRING ConHostArgs = RTL_CONSTANT_STRING(L"\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1");

UNICODE_STRING g_eventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\DumperWait");

HANDLE g_hEvent = NULL;

PKEVENT g_pEvent = NULL;

NTSTATUS WriteDumpFile(
    PVOID Buffer,
    ULONG Length
)
{
    /*
    This function is used to safely write the payload file.
    */
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttr, &OutputFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    status = ZwCreateFile(
        &fileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwWriteFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        Buffer,
        Length,
        NULL,
        NULL
    );

    ZwFlushBuffersFile(fileHandle, &ioStatus);

    ZwClose(fileHandle);
    return status;
}

void WriteStringToLogFile2(PUNICODE_STRING lpStr)
{

    /*
    Writes a PUNICODE_STRING to the logfile
    */
    if (logFileHandle == NULL)
    {
        return;
    }
    IO_STATUS_BLOCK ioStatus;
    ZwWriteFile(
        logFileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        lpStr->Buffer,
        lpStr->Length,
        NULL,
        NULL
    );
    ZwFlushBuffersFile(logFileHandle, &ioStatus);
}

void WriteStringToLogFile(LPCWSTR lpStr)
{
    /*
    Write a LPCWSTR to logfile.
    */
    if (logFileHandle == NULL)
    {
        return;
    }
    IO_STATUS_BLOCK ioStatus;
    ZwWriteFile(
        logFileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        (PVOID)lpStr,
        (ULONG)(wcslen(lpStr) * 2),
        NULL,
        NULL
    );
    ZwFlushBuffersFile(logFileHandle, &ioStatus);
}

typedef struct _DEFERRED_PROCESS_INFO {
    HANDLE pid;
    PIO_WORKITEM workItem;
    LPCWSTR stringVal;
} DEFERRED_PROCESS_INFO, * PDEFERRED_PROCESS_INFO;

VOID LogWorkerRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    //This function is used to ensure that we are writing to the logfile in a safe context only.
    PDEFERRED_PROCESS_INFO pinfo = (PDEFERRED_PROCESS_INFO)Context;
    UNREFERENCED_PARAMETER(DeviceObject);
    WriteStringToLogFile(pinfo->stringVal);
    ExFreePoolWithTag(pinfo->stringVal, 'LSTR');
    IoFreeWorkItem(pinfo->workItem);
    ExFreePoolWithTag(Context, 'LSTR');
}

LPCWSTR ConvertToLStr(PUNICODE_STRING UnicodeString)
{
    LPCWSTR buffer = (LPCWSTR)ExAllocatePoolWithTag(NonPagedPoolNx, UnicodeString->Length + 2, 'LSTR');
    if (buffer)
    {
        memset(buffer, 0x0, UnicodeString->Length + 2);
        RtlCopyMemory(buffer, UnicodeString->Buffer, UnicodeString->Length);
    }
    return buffer;
}

void WriteStringToLogFileSafe(LPCWSTR lpStr)
{
    /*
    Used to write a string to the logfile.  Uses IoQueueWorkItem() to avoid potential issues with running IO functions inside an invalid context.
    */
    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    if (!workItem)
    {
        return;
    }
    SIZE_T bufferLen = (1 + wcslen(lpStr)) * sizeof(WCHAR);
    LPCWSTR copy = (LPCWSTR)ExAllocatePoolWithTag(NonPagedPoolNx, bufferLen, 'LSTR');
    if (!copy)
    {
        return;
    }

    PDEFERRED_PROCESS_INFO pinfo = (PDEFERRED_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(DEFERRED_PROCESS_INFO), 'LSTR');
    if (!pinfo)
    {
        ExFreePoolWithTag(copy, 'LSTR');
        return;
    }
    RtlCopyMemory(copy, lpStr, bufferLen);
    pinfo->workItem = workItem;
    pinfo->stringVal = copy;
    IoQueueWorkItem(workItem, LogWorkerRoutine, DelayedWorkQueue, pinfo);
}

HANDLE CreateLogFile()
{
    //Create the logfile.
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttr, &LogFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    status = ZwCreateFile(
        &fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    return fileHandle;
}

BOOL IsConHost(PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    //Checks if a process command line matches the hardcoded conhost string above.
    //This is because guloader will normally start a conhost process and we want to ignore it.
    return RtlCompareUnicodeString(CreateInfo->CommandLine, &ConHostArgs, FALSE) == 0;
}

VOID OnProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    /*
    This function represents one of the key ways that GuloaderDumper tracks guloaders inject process.
    */

    wchar_t buffer[260];
    memset(buffer, 0x0, sizeof(buffer));
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        // Process is being created
        HANDLE parentPid = CreateInfo->ParentProcessId;
        if (IsConHost(CreateInfo))
        {
            WriteStringToLogFileSafe(L"Skipping process because its conhost.exe\n");
            return;
        }
        if (amtProcesses == 1) //If we already have a process, the next process created by the process will likely be the next target process in the chain.
        {
            if (parentPid == targetProcess)
            {
                DbgPrint("swapping to secondary process %lld\n", (UINT64)ProcessId);
                _snwprintf(buffer, 259, L"swapping from %lld to %lld\n", (UINT64)targetProcess, (UINT64)ProcessId);
                WriteStringToLogFileSafe(buffer);
                currentProcess = ProcessId;
                amtProcesses++;
            }
        }
        else
        {
            if (parentPid == currentProcess) //This is another case to handle for process swaps - if the secondary process creates a child process.
            {
                DbgPrint("Swapping to secondary process 2 %lld\n", (UINT64)ProcessId);
                _snwprintf(buffer, 259, L"swapping from %lld to %lld\n", (UINT64)currentProcess, (UINT64)ProcessId);
                WriteStringToLogFileSafe(buffer);
                currentProcess = ProcessId;
                amtProcesses++;
            }
        }
        //Through this function we can keep track of which process number guloader will attempt to inject itself into.

    }
}

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    // ... more fields if needed
} LDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    // ...
} PEB_LDR_DATA32;

typedef struct _PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG Reserved3[2];
    ULONG Ldr; // PEB_LDR_DATA32*
    // ...
} PEB32;

//Some experimental IAT fixups that I never finished since it didnt really seem to affect the binaries produced.  Something for later.
static void ZeroIATWhenOFTPresent(PUCHAR imageBase)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(imageBase + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) return;

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + impDir.VirtualAddress);
    if (!imp) return;

    for (; imp->Name != 0; ++imp) {

        if (imp->OriginalFirstThunk == 0) {
            continue;
        }

        IMAGE_THUNK_DATA32* oft = (IMAGE_THUNK_DATA32*)imageBase + imp->OriginalFirstThunk;
        IMAGE_THUNK_DATA32* iat = (IMAGE_THUNK_DATA32*)imageBase + imp->FirstThunk;
        if (!oft || !iat) {
            continue;
        }

        while (oft->u1.AddressOfData != 0) {
            iat->u1.Function = 0;
            ++oft; ++iat;
        }
    }
}


PVOID SquashExecutable(PUCHAR vExe, SIZE_T vExeSize, PSIZE_T lpOutExeSize, PVOID targetImage)
{
    /*
    Take the already memory mapped process executable, squish it to file format and then add some fixups.
    */
    if (!lpOutExeSize || !vExe || vExeSize == 0)
    {
        return NULL;
    }
    //ZeroIATWhenOFTPresent(vExe);
    IMAGE_DOS_HEADER * dos_header = (IMAGE_DOS_HEADER*)vExe;
    IMAGE_NT_HEADERS32* nt_headers32 = (IMAGE_NT_HEADERS32*)(vExe + dos_header->e_lfanew);
    SIZE_T totalSquashedSize = nt_headers32->OptionalHeader.SizeOfHeaders;
    IMAGE_SECTION_HEADER* sec_hdrs = (IMAGE_SECTION_HEADER*)(vExe + dos_header->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers32->FileHeader.SizeOfOptionalHeader);
    for (int x = 0; x < nt_headers32->FileHeader.NumberOfSections; x++)
    {
        //Calculate how big our binary should be at the end.
        IMAGE_SECTION_HEADER sechdr = sec_hdrs[x];
        totalSquashedSize += (sechdr.PointerToRawData - totalSquashedSize);
        totalSquashedSize += sechdr.SizeOfRawData;
    }

    totalSquashedSize += (512 - (totalSquashedSize % 512)) % 512;

    PUCHAR newImage = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, totalSquashedSize, 'ImgB');
    if (!newImage)
    {
        return NULL;
    }

    RtlZeroMemory(newImage, totalSquashedSize); //zero out memory to be safe
    //Copy the headers over.  Unlikely to be any change here.
    RtlCopyMemory(newImage, vExe, nt_headers32->OptionalHeader.SizeOfHeaders);
    for (int x = 0; x < nt_headers32->FileHeader.NumberOfSections; x++)
    {
        IMAGE_SECTION_HEADER sechdr = sec_hdrs[x]; //Copy the sections over.
        RtlCopyMemory(newImage + sechdr.PointerToRawData, vExe + sechdr.VirtualAddress, sechdr.SizeOfRawData);
    }

    IMAGE_DOS_HEADER * newDos = (IMAGE_DOS_HEADER*)newImage; 
    IMAGE_NT_HEADERS32* newHeaders = (IMAGE_NT_HEADERS32*)((char*)newImage + newDos->e_lfanew);
    newHeaders->OptionalHeader.ImageBase = (DWORD)targetImage; //Change imagebase to ensure relocs compatibility.
    

    *lpOutExeSize = totalSquashedSize;
    return (PVOID)newImage;
}

VOID DumpExecutable(PEPROCESS proc)
{
    /*
    Procedure that results in the memory mapped executable being dumped from a process.
    */
    PVOID imageBase = PsGetProcessSectionBaseAddress(proc); //First get our base address for the process.
    KAPC_STATE apcState;
    if (imageBase == 0)
    {
        return;
    }

    if (PsGetProcessWow64Process(proc) == NULL) //We dont support 64bit files yet which is fine because guloader seems to be 32 bit mostly.
    {
        return;
    }
    PVOID targetImage = NULL;
    BOOL error = FALSE;
    PsSuspendProcess(proc); //Suspend the process before dumping to be safe.
    __try
    {
        //For guloader dumps we want to target the module in the process that contains the payload.
        KeStackAttachProcess(proc, &apcState); //Attach ourselves to the process.
        PEB32* peb = (PEB32*)PsGetProcessWow64Process(proc); //Get the PEB.  We need the module linked list.
        PEB_LDR_DATA32* ldr = (PEB_LDR_DATA32*)peb->Ldr;
        LIST_ENTRY32* listHead = &ldr->InMemoryOrderModuleList;
        LIST_ENTRY32* current = (LIST_ENTRY32*)listHead->Flink;
        /*
        So this is where the main logic really happens.  Once guloader completes injection, the injected executable does end up within this list.
        The next question becomes which executable is it?
        Guloader does sort of tell us that.  When loading it into memory, if we check the characteristics from the header it will show as an EXE file.
        Everything else in this list will probably be a DLL.
        */
        while (current && current != listHead)
        {
            LDR_DATA_TABLE_ENTRY32 *entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
            if (((PVOID)entry->DllBase) != imageBase)
            {
                IMAGE_DOS_HEADER* dosHead = (IMAGE_DOS_HEADER*)entry->DllBase;
                ULONG fileOffset = dosHead->e_lfanew + 4;
                IMAGE_FILE_HEADER* fileHead = (IMAGE_FILE_HEADER*)(((PUCHAR)entry->DllBase) + fileOffset);
                //Guloader seems to be nice enough to load the payload strictly into a fake module that is not marked as a DLL.
                if ((fileHead->Characteristics & 0x2) != 0 && (fileHead->Characteristics & 0x2000) == 0)
                {
                    targetImage = (PVOID)entry->DllBase;
                    break;
                }
            }
            current = (LIST_ENTRY32*)current->Flink;
        }

        if (targetImage == NULL)
        {
            error = TRUE;
            __leave;
        }

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)targetImage;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            error = TRUE;
            __leave;
        }

        ULONG optionalOffset = dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
        IMAGE_OPTIONAL_HEADER32* opt = (IMAGE_OPTIONAL_HEADER32*)((PUCHAR)targetImage + optionalOffset);
        PVOID imageCopy = ExAllocatePoolWithTag(NonPagedPoolNx, opt->SizeOfImage, 'ImgB');
        if (!imageCopy)
        {
            error = TRUE;
            __leave;
        }

        RtlCopyMemory(imageCopy, targetImage, opt->SizeOfImage);
        SIZE_T squashedSize = 0;
        PVOID squashedExe = SquashExecutable(imageCopy, opt->SizeOfImage, &squashedSize, targetImage);
        if (!squashedExe)
        {
            ExFreePoolWithTag(imageCopy, 'ImgB');
            error = TRUE;
            __leave;
        }

        WriteDumpFile(squashedExe, (ULONG)squashedSize);
        if (g_pEvent)
        {
            KeSetEvent(g_pEvent, IO_NO_INCREMENT, FALSE); //set the event to let the runner know dumping is complete.
            ObDereferenceObject(g_pEvent);
            ZwClose(g_hEvent);
            g_pEvent = NULL;
            g_hEvent = NULL;
        }
        ExFreePoolWithTag(imageCopy, 'ImgB');
        ExFreePoolWithTag(squashedExe, 'ImgB');
        __leave;

    }
    __finally
    {
        KeUnstackDetachProcess(&apcState);
    }

    if (targetImage != NULL)
    {
        wchar_t buffer[240];
        memset(buffer, 0x0, sizeof(buffer));
        _snwprintf(buffer, 239, L"Dumped memory at %llx\n", (UINT64)targetImage);
        WriteStringToLogFile(buffer);
    }
    else
    {
        WriteStringToLogFile(L"Could not determine target memory\n");
    }

    if (error)
    {
        WriteStringToLogFile(L"Error dumping\n");
    }
    else
    {
        WriteStringToLogFile(L"Dump completed\n");
    }
}

VOID WorkerFn(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    //Again avoids context issues by putting most of the work into an IoQueueWorkItem().
    if (!Context)
    {
        return;
    }
    UNREFERENCED_PARAMETER(DeviceObject);
    PDEFERRED_PROCESS_INFO info = (PDEFERRED_PROCESS_INFO)Context;

    LARGE_INTEGER interval;
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process;
    interval.QuadPart = -30 * 10000000LL; // 60 seconds in 100ns units, negative = relative time
    //KeDelayExecutionThread(KernelMode, FALSE, &interval); //We probably dont need this since it seems to be all good by the time MyDeleteFlow is called.

    status = PsLookupProcessByProcessId(info->pid, &process);
    if (NT_SUCCESS(status))
    {
        DbgPrint("Attempting to dump executable for process %lld\n", (UINT64)info->pid);
        WriteStringToLogFile(L"Dumping executable\n");
        DumpExecutable(process);
        ObDereferenceObject(process);
        //Now that it actually works do we Terminate execution here?
    }
    IoFreeWorkItem(info->workItem);
    ExFreePoolWithTag(info, '60WT');
}

BOOL g_AlreadyDumped = FALSE;

typedef struct _LOG_STRING_INFO {
    PIO_WORKITEM workItem;
    UINT32 eventType;
    UINT64 argOne;
    UINT64 argTwo;
    UINT32 argThree;
} LOG_STRING_INFO, * PLOG_STRING_INFO;


VOID LogStringWorkFn(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    if (Context == 0)
        return;
    wchar_t buffer[0x200];
    memset(buffer, 0x0, sizeof(buffer));
    PLOG_STRING_INFO info = (PLOG_STRING_INFO)Context;
    if (info->eventType == 1)
    {
        _snwprintf(buffer, 0x200 - 1, L"Queueing work item %lld\n", (UINT64)info->argOne);
    }
    else if (info->eventType == 2)
    {
        _snwprintf(buffer, 0x200-1, L"Got a connection from %lld %lld %d\n", (UINT64)info->argOne, (UINT64)info->argTwo, info->argThree);
    }
    WriteStringToLogFile(buffer);
    IoFreeWorkItem(info->workItem);
    ExFreePoolWithTag(info, '60WT');
}

VOID NTAPI
MyFlowDeleteFn(
    UINT16 layerId,
    UINT32 calloutId2,
    UINT64 flowContext)
{
    /*
    This here is another major part of the functionality.

    Guloader downloads its payload from the internet.  In order to know when exactly we can pull it, we need some sort of metric.
    Since guloader downloads from the internet, we can use when the connection is closed to determine a time when dumping will be possible.
    */
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId2);
    if (flowContext != 0 && !g_AlreadyDumped)
    {
        g_AlreadyDumped = TRUE;
        PDEFERRED_PROCESS_INFO pInfo = (PDEFERRED_PROCESS_INFO)flowContext;
        PLOG_STRING_INFO lInfo = (PLOG_STRING_INFO)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PLOG_STRING_INFO), '60WT');
        if (lInfo)
        {
            lInfo->workItem = IoAllocateWorkItem(g_DeviceObject);
            lInfo->eventType = 1;
            lInfo->argOne = (UINT64)pInfo->pid;
            IoQueueWorkItem(lInfo->workItem, LogStringWorkFn, DelayedWorkQueue, lInfo);
        }
        IoQueueWorkItem(pInfo->workItem, WorkerFn, DelayedWorkQueue, pInfo);
    }
}

VOID NTAPI ConnectClassifyFn(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    VOID* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(inFixedValues);
    classifyOut->actionType = FWP_ACTION_PERMIT;

    /*
    Another function heavily involved in dumping.
    Its purpose is to tag relevant connections with a PDEFFERED_PROCESS_INFO which is needed for the connection delete callback.
    */

    NTSTATUS connectStatus = inMetaValues->transportEndpointHandle
        ? STATUS_SUCCESS
        : STATUS_CONNECTION_REFUSED;
    HANDLE pid = (HANDLE)inMetaValues->processId;

    PLOG_STRING_INFO lInfo = (PLOG_STRING_INFO)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PLOG_STRING_INFO), '60WT');
    if (lInfo && pid == currentProcess)
    {
        lInfo->workItem = IoAllocateWorkItem(g_DeviceObject);
        lInfo->eventType = 2;
        lInfo->argOne = (UINT64)pid;
        lInfo->argTwo = (UINT64)currentProcess;
        lInfo->argThree = connectStatus == STATUS_SUCCESS;
        IoQueueWorkItem(lInfo->workItem, LogStringWorkFn, DelayedWorkQueue, lInfo);
    }
    if (pid == currentProcess && connectStatus == STATUS_SUCCESS)
    {
        //Queue up the memory dump here.
        PDEFERRED_PROCESS_INFO pInfo = (PDEFERRED_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(DEFERRED_PROCESS_INFO), '60WT');
        if (!pInfo)
        {
            return;
        }


        pInfo->workItem = IoAllocateWorkItem(g_DeviceObject);
        pInfo->pid = pid;
        FwpsFlowAssociateContext(inMetaValues->flowHandle, FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4, calloutId, (UINT64)pInfo);

        //IoQueueWorkItem(pInfo->workItem, WorkerFn, DelayedWorkQueue, pInfo);

    }

}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    //Cleanup everything driver related to unload safely.
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_filterId)
    {
        FwpmFilterDeleteById(g_EngineHandle, g_filterId);
        FwpmSubLayerDeleteByKey(g_EngineHandle, &SUB_LAYER_GUID);
        g_filterId = 0;
    }

    if (addCalloutId)
    {
        FwpmCalloutDeleteById(g_EngineHandle, addCalloutId);
        addCalloutId = 0;
    }

    if (calloutId)
    {
        FwpsCalloutUnregisterById(calloutId);
        calloutId = 0;
    }

    if (g_EngineHandle)
    {
        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotifyEx, TRUE);
    if (logFileHandle != NULL)
    {
        ZwClose(logFileHandle);
    }

    if (g_DeviceObject != NULL)
    {
        IoDeleteSymbolicLink(&g_SymbolicLinkName);
        IoDeleteDevice(g_DeviceObject);
    }

    if (g_pEvent != NULL)
    {
        ObDereferenceObject(g_pEvent);
    }

    if (g_hEvent != NULL)
    {
        ZwClose(g_hEvent);
    }
}

NTSTATUS CalloutNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

NTSTATUS CreateGlobalEvent(void)
{
    //Create a global event to notify the user once were done dumping.
    NTSTATUS st;
    OBJECT_ATTRIBUTES oa;

    InitializeObjectAttributes(&oa,
        &g_eventName,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL,
        NULL);

    st = ZwCreateEvent(&g_hEvent, EVENT_ALL_ACCESS, &oa, NotificationEvent, FALSE);
    if (!NT_SUCCESS(st)) {
        WriteStringToLogFile(L"ZwCreateEvent Failed\n");
        g_hEvent = NULL;
        return st;
    }

    // Get a referenced PKEVENT for KeSetEvent/KeClearEvent
    st = ObReferenceObjectByHandle(g_hEvent,
        EVENT_MODIFY_STATE | SYNCHRONIZE,
        *ExEventObjectType,
        KernelMode,
        (PVOID*)&g_pEvent,
        NULL);
    if (!NT_SUCCESS(st)) {
        WriteStringToLogFile(L"ObReferenceObjectByHandle failed");
        ZwClose(g_hEvent);
        g_hEvent = NULL;
        return st;
    }

    KeClearEvent(g_pEvent);
    return STATUS_SUCCESS;
}

VOID CreateDoneEvent()
{
    //Create the done event.
    if (g_pEvent != NULL)
    {
        return;
    }
    NTSTATUS status = CreateGlobalEvent();
    if (!NT_SUCCESS(status))
    {
        wchar_t buffer[20];
        WriteStringToLogFile(L"IoCreateNotificationEvent Failed\n");
        memset(buffer, 0x0, sizeof(buffer));
        _snwprintf(buffer, 19, L"%x\n", status);
        WriteStringToLogFile(buffer);
    }
    else
    {
        WriteStringToLogFile(L"Init event complete.\n");
    }

}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    /*
    IOCTL handler for the driver.  Its sole purpose is to obtain our initial target process from the runner python script.
    */
    UNREFERENCED_PARAMETER(DeviceObject);
    wchar_t buffer[40];
    memset(buffer, 0x0, sizeof(buffer));
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);    
    memset(buffer, 0x0, sizeof(buffer));

    if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SEND_PID)
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
            ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
            DbgPrint("Keeping track of initial process %lx\n", (ULONG)pid);

            memset(buffer, 0x0, sizeof(buffer));
            _snwprintf(buffer, 19, L"%d\n", pid);

            WriteStringToLogFile(L"Keeping track of initial process\n");
            WriteStringToLogFile(buffer);
            targetProcess = (HANDLE)pid;
            amtProcesses = 1;
            CreateDoneEvent();
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
    logFileHandle = CreateLogFile();
    DbgPrint("Reached DriverEntry\n");
    WriteStringToLogFile(L"Reached DriverEntry\n");
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    // NTSTATUS variable to record success or failure
    NTSTATUS status = STATUS_SUCCESS;
    status = IoCreateDevice(  //Create a device for the driver
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("IoCreateDevice failed with status %x\n", status);
        WriteStringToLogFile(L"IoCreateDevice failed\n");
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymbolicLinkName, &devName); //Symlink it so that userspace can access.

    if (!NT_SUCCESS(status))
    {
        DbgPrint("IoRegisterDeviceInterface failed\n");
        WriteStringToLogFile(L"IoRegisterDeviceInterface failed\n");
        DriverUnload(NULL);
        return status;
    }
    
    status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotifyEx, FALSE); //Create a process notify handler.
    if (!NT_SUCCESS(status))
    {
        DbgPrint("PsSetCreateProcessNotifyRoutineEx failed\n");
        WriteStringToLogFile(L"PSSetCreateProcessNotifyRoutineEx failed\n");
        DriverUnload(NULL);
        return status;
    }

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_EngineHandle); //Start setup for network filters.
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Error on FwpmEngineOpen\n");
        WriteStringToLogFile(L"FwpmEngineOpen failed\n");
        DriverUnload(NULL);
        return status;
    }

    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = YOUR_CALLOUT_GUID;
    callout.classifyFn = ConnectClassifyFn;
    callout.notifyFn = CalloutNotify;
    callout.flowDeleteFn = MyFlowDeleteFn;
    status = FwpsCalloutRegister(g_DeviceObject, &callout, &calloutId);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("FwpsCalloutRegister failed with status code %x\n", status);
        WriteStringToLogFile(L"FwpsCalloutRegister failed\n");
        DriverUnload(NULL);
        return status;
    }

    status = FwpmTransactionBegin(g_EngineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Error starting transaction\n");
        WriteStringToLogFile(L"Error with FwpmTransactionbegin\n");
        DriverUnload(NULL);
        return status;
    }

    FWPM_CALLOUT fwpm_callout = {
        .flags = 0,
        .displayData.name = L"ilikepie",
        .displayData.description = L"ilikepie",
        .calloutKey = YOUR_CALLOUT_GUID,
        .applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4

    };
    status = FwpmCalloutAdd(g_EngineHandle, &fwpm_callout, NULL, &addCalloutId);

    if (!NT_SUCCESS(status))
    {
        WriteStringToLogFile(L"FwpmCalloutAdd failed\n");
        DbgPrint("FwpmCalloutAdd failed\n");
        DriverUnload(NULL);
        return status;
    }

    FWPM_SUBLAYER sublayer = {
        .displayData.name = L"ilikepiesublayer",
        .displayData.name = L"ilikepiesublayer",
        .subLayerKey = SUB_LAYER_GUID,
        .weight = 65535
    };

    status = FwpmSubLayerAdd(g_EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
    {
        WriteStringToLogFile(L"FwpmSubLayerAdd failed\n");
        DbgPrint("FwpmSubLayerAdd failed\n");
        DriverUnload(NULL);
        return status;
    }

    UINT64      weightValue = 0xFFFFFFFFFFFFFFFF;                             // Max UINT64 value
    FWP_VALUE   weight = { .type = FWP_UINT64, .uint64 = &weightValue };

    FWPM_FILTER_CONDITION condition = {
        .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
        .matchType = FWP_MATCH_EQUAL,
        .conditionValue.type = FWP_UINT8,
        .conditionValue.uint8 = IPPROTO_TCP
    };

    FWPM_FILTER_CONDITION conditions[] = { condition };

    FWPM_FILTER filter = {
        .displayData.name = L"ilikepiefilter",
        .displayData.description = L"ilikepiefilterdesc",
        .layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        .subLayerKey = SUB_LAYER_GUID,
        .weight = weight,
        .numFilterConditions = 1,
        .filterCondition = conditions,
        .action.type = FWP_ACTION_CALLOUT_INSPECTION,
        .action.calloutKey = YOUR_CALLOUT_GUID
    };

    status = FwpmFilterAdd(g_EngineHandle, &filter, NULL, &g_filterId);
    if (!NT_SUCCESS(status))
    {
        WriteStringToLogFile(L"Error on FwpmFilterAdd\n");
        DriverUnload(NULL);
        return status;
    }

    status = FwpmTransactionCommit(g_EngineHandle);
    if (!NT_SUCCESS(status))
    {
        WriteStringToLogFile(L"Error could not commit transaction\n");
        DriverUnload(NULL);
        DbgPrint("Error FwpmTransactionCommit\n");
        return status;
    }

    return STATUS_SUCCESS;
}