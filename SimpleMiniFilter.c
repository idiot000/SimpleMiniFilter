#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdio.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define SF_FILTER_NAME L"SimpleMiniFilter"



/////////////////////////////////////////////////////////////////////////////////
//  Temporary Defines                                                          //
/////////////////////////////////////////////////////////////////////////////////

#define SF_STREAM_CONTEXT_POOL_TAG      'xSfS'
#define SF_STRING_POOL_TAG              'rSfS'

#define SF_CONTEXT_POOL_TYPE            PagedPool

//Tag names for memory allocated from pool, 
//can be displayed while debugging in reverse order
/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Temporary Macros                                                           //
/////////////////////////////////////////////////////////////////////////////////
#define SF_PRINT( ... )                                                      \
    DbgPrintEx( DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__ )

#define SF_DBG_PRINT( _dbgLevel, ... )                                       \
    (FlagOn( gTraceFlags, (_dbgLevel) ) ?                                    \
        DF_PRINT( __VA_ARGS__ ):                                             \
        (0))

#define FlagOnAll( F, T )                                                    \
    (FlagOn( F, T ) == T)
/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Structures                                                                 //
/////////////////////////////////////////////////////////////////////////////////

//filter specific data
typedef struct _SF_DATA {
	PFLT_FILTER FilterHandle;
	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;
	PEPROCESS UserProcess;
} SF_DATA, *PSF_DATA;


typedef struct _SF_STREAM_CONTEXT {
	PFLT_FILE_NAME_INFORMATION	nameInfo;
	volatile LONG	numOps;
	volatile LONG	isNotified;
	BOOLEAN		setDisp;
	BOOLEAN		deleteOnClose;
} SF_STREAM_CONTEXT, *PSF_STREAM_CONTEXT;


//usermode communication msg
typedef struct _SF_MESSAGE {
	WCHAR Contents[1024];
} SF_MESSAGE, *PSF_MESSAGE;

//volatile variables change often (race conditions), change visible immediately
/////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////
//  Prototypes                                                                 //
/////////////////////////////////////////////////////////////////////////////////

DRIVER_INITIALIZE DriverEntry;

NTSTATUS 
DriverEntry(
	__in PDRIVER_OBJECT DriverObject, 
	__in PUNICODE_STRING RegistryPath
	);

NTSTATUS 
SimpleUnload(
	__in FLT_FILTER_UNLOAD_FLAGS Flags
	);

NTSTATUS 
SimpleInstanceSetup(
	__in PCFLT_RELATED_OBJECTS FltObjects, 
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType, 
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
	);

NTSTATUS 
SimpleQueryTeardown(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS 
SfPreCreateCallback(
	__inout PFLT_CALLBACK_DATA Data, 
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS  
SfPostCreateCallback(
	__inout PFLT_CALLBACK_DATA Data, 
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext, 
	__in FLT_POST_OPERATION_FLAGS Flags
	);

FLT_POSTOP_CALLBACK_STATUS
SfPostWriteCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS
SfPreSetInfoCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS
SfPostSetInfoCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS
SfPreCleanupCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS
SfPostCleanupCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

VOID
SfStreamContextCleanupCallback(
	__in PSF_STREAM_CONTEXT streamContext,
	__in FLT_CONTEXT_TYPE ContextType
	);

NTSTATUS 
SfPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionPortCookie
	);

VOID 
SfPortDisconnect(
	__in_opt PVOID ConnectionCookie
	);

NTSTATUS
SfGetFileNameInformation(
	__in PFLT_CALLBACK_DATA Data,
	__inout PSF_STREAM_CONTEXT StreamContext
	);

NTSTATUS
SfAllocateUnicodeString(
	__inout PUNICODE_STRING String
	);

VOID
SfFreeUnicodeString(
	__inout PUNICODE_STRING String
	);

NTSTATUS
SfIsFileDeleted(
	__in PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects
	);

NTSTATUS
SfProcessDelete(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PSF_STREAM_CONTEXT StreamContext
	);

NTSTATUS
SfGetOrSetContext(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID Target,
	__inout_opt PFLT_CONTEXT *Context
	);

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Main Globals															   //
/////////////////////////////////////////////////////////////////////////////////

SF_DATA SfData;

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Text section assignments for all callbacks                                 //
/////////////////////////////////////////////////////////////////////////////////
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SimpleUnload)
#pragma alloc_text(PAGE, SimpleInstanceSetup)
#pragma alloc_text(PAGE, SimpleQueryTeardown)
#pragma alloc_text(PAGE, SfPreCreateCallback)
#pragma alloc_text(PAGE, SfPostCreateCallback)
#pragma alloc_text(PAGE, SfPostWriteCallback)
#pragma alloc_text(PAGE, SfPreSetInfoCallback)
#pragma alloc_text(PAGE, SfPostSetInfoCallback)
#pragma alloc_text(PAGE, SfPreCleanupCallback)
#pragma alloc_text(PAGE, SfPostCleanupCallback)
#pragma alloc_text(PAGE, SfStreamContextCleanupCallback)
#pragma alloc_text(PAGE, SfPortConnect)
#pragma alloc_text(PAGE, SfPortDisconnect)
#pragma alloc_text(PAGE, SfGetFileNameInformation)
#pragma alloc_text(PAGE, SfAllocateUnicodeString)
#pragma alloc_text(PAGE, SfFreeUnicodeString)
#pragma alloc_text(PAGE, SfIsFileDeleted)
#pragma alloc_text(PAGE, SfProcessDelete)
#pragma alloc_text(PAGE, SfGetOrSetContext)
#endif
//pragma, machine/OS specific compiler directive
//INIT (non-pageable routines, discarded as soon as DriverEntry returns)
/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Operation Registration (Major Functions)							       //
/////////////////////////////////////////////////////////////////////////////////
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	
	{	IRP_MJ_CREATE,									//major function
		0,												//flags
		SfPreCreateCallback,							//preoperation
		SfPostCreateCallback	},						//postoperation

	{
		IRP_MJ_WRITE,
		0,	
		NULL,
		SfPostWriteCallback		}, 

	{	IRP_MJ_SET_INFORMATION,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		SfPreSetInfoCallback,
		SfPostSetInfoCallback	},

    {	IRP_MJ_CLEANUP,
		0,
		SfPreCleanupCallback,
		SfPostCleanupCallback	},

	{	IRP_MJ_OPERATION_END	}						//final member
};
/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Context Registration							                           //
/////////////////////////////////////////////////////////////////////////////////
CONST FLT_CONTEXT_REGISTRATION Contexts[] = {

	{ FLT_STREAM_CONTEXT,							//context type
	  0,											//flags
	  SfStreamContextCleanupCallback,				//context cleanup callback
	  sizeof(SF_STREAM_CONTEXT),					//size of context
	  SF_STREAM_CONTEXT_POOL_TAG,					//pooltag
	  NULL,											//context allocate callback
	  NULL,											//context free callback
	  NULL },										//reserved
	
	{ FLT_CONTEXT_END }								//final member

};
/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Filter Registration							                               //
/////////////////////////////////////////////////////////////////////////////////
CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),						//size
	FLT_REGISTRATION_VERSION,						//version
	0,												//flags
	Contexts,										//context
	Callbacks,										//operation callbacks
	SimpleUnload,									//FilterUnload
	SimpleInstanceSetup,							//InstanceSetup
	SimpleQueryTeardown,							//InstanceQueryTeardown
	NULL,											//InstanceTeardownStart
	NULL,											//InstanceTeardownComplete
	NULL,											//GenerateFileName
	NULL,											//NormalizeNameComponent
	NULL											//NormalizeContextCleanup
};
/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Driver initialization and unload routines								   //
/////////////////////////////////////////////////////////////////////////////////

NTSTATUS 
DriverEntry(
	__in PDRIVER_OBJECT DriverObject, 
	__in PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS status, pstatus;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;

	const PCWSTR SimplePortName = L"\\SimplePort";

	UNREFERENCED_PARAMETER(RegistryPath);

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &SfData.FilterHandle);

	if(NT_SUCCESS(status))
	{
		RtlInitUnicodeString(&uniString, SimplePortName);

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS); 	//FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL

		if(NT_SUCCESS(status))
		{
			InitializeObjectAttributes(&oa, 									//OA
									   &uniString, 								//name
									   OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, 	//attributes
									   NULL, 									//root directory
									   sd);										//security descriptor

			pstatus = FltCreateCommunicationPort(SfData.FilterHandle, 			//filter
												 &SfData.ServerPort,			//used by driver to listen for incomming cons. by usermode
												 &oa, 							//attributes for server port
												 NULL, 							//contextcookie
												 SfPortConnect, 				//connectnotifycallback
												 SfPortDisconnect, 				//disconnectnotifycallback
												 NULL, 							//messagenotifycallback
												 1);							//max connections
			FltFreeSecurityDescriptor(sd);

			if(!NT_SUCCESS(pstatus))
				DbgPrint("Could not create ComPort, status 0x%X\n", pstatus);
			else
				DbgPrint("ComPort created successfully\n");
		}

		status = FltStartFiltering(SfData.FilterHandle);

		if( (!NT_SUCCESS(status)) && (NT_SUCCESS(pstatus)) )
		{
				FltUnregisterFilter(SfData.FilterHandle);
				FltCloseCommunicationPort(SfData.ServerPort);
		}
		else if( (!NT_SUCCESS(status)) && (!NT_SUCCESS(pstatus)) )
			FltUnregisterFilter(SfData.FilterHandle);
	}

	return status;
}


NTSTATUS 
SimpleUnload(
	__in FLT_FILTER_UNLOAD_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	DbgPrint("SimpleUnload: entered\n");

	FltCloseCommunicationPort(SfData.ServerPort);

	FltUnregisterFilter(SfData.FilterHandle);

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Instance Setup Routines (Setup/QueryTeardown)							   //
/////////////////////////////////////////////////////////////////////////////////

NTSTATUS 
SimpleInstanceSetup(									//called a new instance/volume attaches
	__in PCFLT_RELATED_OBJECTS FltObjects, 				
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType, 
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	DbgPrint("SimpleInstanceSetup: entered\n");
	DbgPrint("New instance attached!\n");

	return STATUS_SUCCESS;
}


NTSTATUS 
SimpleQueryTeardown(									//called when a volume/instance is to be manually detached
	__in PCFLT_RELATED_OBJECTS FltObjects, 
	__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	DbgPrint("SimpleQueryTeardown: entered\n");

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  "Connection with usermode" routines										   //
/////////////////////////////////////////////////////////////////////////////////

NTSTATUS 
SfPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
	)
{
	PAGED_CODE();

	ASSERT(SfData.UserProcess == NULL);
	ASSERT(SfData.ClientPort == NULL);

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	DbgPrint("SfPortConnect: entered\n");

	SfData.UserProcess = PsGetCurrentProcess();
	SfData.ClientPort = ClientPort;

	return STATUS_SUCCESS;
}


VOID 
SfPortDisconnect(
	__in_opt PVOID ConnectionCookie
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	DbgPrint("SfPortDisconnect: entered\n");

	FltCloseClientPort(SfData.FilterHandle, &SfData.ClientPort);

	SfData.UserProcess = NULL;
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Operation Callback routines												   //
/////////////////////////////////////////////////////////////////////////////////

FLT_PREOP_CALLBACK_STATUS 
SfPreCreateCallback(
	__inout PFLT_CALLBACK_DATA Data, 
	__in PCFLT_RELATED_OBJECTS FltObjects,				//FLT_RELATED_OBJECTS, objects related with an operation
	__deref_opt_out PVOID *CompletionContext
	)
{
	NTSTATUS status;
	PSF_STREAM_CONTEXT streamContext;

	UNREFERENCED_PARAMETER(FltObjects);

	PAGED_CODE();

	if(FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE))
	{
		
		status = FltAllocateContext(SfData.FilterHandle,
									FLT_STREAM_CONTEXT,
									sizeof(SF_STREAM_CONTEXT),
									SF_CONTEXT_POOL_TYPE,
									(PFLT_CONTEXT*)&streamContext);
		if(NT_SUCCESS(status))
		{
			RtlZeroMemory(streamContext, sizeof(SF_STREAM_CONTEXT));
			*CompletionContext = (PVOID)streamContext;
		}
		else
			*CompletionContext = NULL;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS 
SfPostCreateCallback(
	__in PFLT_CALLBACK_DATA Data, 
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext, 
	__in FLT_POST_OPERATION_FLAGS Flags
	)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION fileNameInfo;
	PSF_STREAM_CONTEXT streamContext = NULL;
	PSF_MESSAGE message = NULL;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	if(Data->IoStatus.Information == FILE_CREATED)
	{

		status = FltGetFileNameInformation(Data, 
										   FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT, 
										   &fileNameInfo);
		if(NT_SUCCESS(status))
		{
			FltParseFileNameInformation(fileNameInfo);

			message = (PSF_MESSAGE)ExAllocatePoolWithTag(NonPagedPool, sizeof(SF_MESSAGE), 'pmiS');

			if(message != NULL)
			{
				int i;
				for(i = 0; i <= fileNameInfo->Name.Length; i++)
				{
					if(i != fileNameInfo->Name.Length)
						message->Contents[i] = fileNameInfo->Name.Buffer[i];
					else
						message->Contents[i] = '\0';
				}
		
				status = FltSendMessage(SfData.FilterHandle, 
										&SfData.ClientPort, 
										message, 
										sizeof(SF_MESSAGE),
										NULL, 
										NULL, 
										NULL);

				if(NT_SUCCESS(status))
					DbgPrint("Message Sent!\n");
				else
					DbgPrint("%wZ created/opened, status 0x%X\n", &fileNameInfo->Name, status);

				ExFreePoolWithTag(message, 'pmiS');
			}
			else
				DbgPrint("%wZ created/opened\n", &fileNameInfo->Name);

			FltReleaseFileNameInformation(fileNameInfo);
		}
	}
	
	if(CompletionContext != NULL)
	{
		//DbgPrint("SfPostCreateCallback: entered\n");

		streamContext = (PSF_STREAM_CONTEXT)CompletionContext;

		if(NT_SUCCESS(Data->IoStatus.Status) && (Data->IoStatus.Status != STATUS_REPARSE)) //reparse should be performed
		{																				   //as filename is symbolic
			ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

			status = SfGetOrSetContext(FltObjects,
									   Data->Iopb->TargetFileObject,
									   (PFLT_CONTEXT*)&streamContext);
			if(NT_SUCCESS(status))
				streamContext->deleteOnClose = BooleanFlagOn(Data->Iopb->Parameters.Create.Options, 
															 FILE_DELETE_ON_CLOSE); //iopb -> FLT_IO_PARAMETER_BLOCK
		}

		if(NT_SUCCESS(status))
			FltReleaseContext(streamContext);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS
SfPostWriteCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION fileNameInfo;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	status = FltGetFileNameInformation(Data,
									   FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT,
									   &fileNameInfo);
	if(!NT_SUCCESS(status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	status = FltParseFileNameInformation(fileNameInfo);

	if(!NT_SUCCESS(status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	DbgPrint("File written to: %wZ\n", &fileNameInfo->Name);

	FltReleaseFileNameInformation(fileNameInfo);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
SfPreSetInfoCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	)
{
	NTSTATUS status;
	PSF_STREAM_CONTEXT streamContext = NULL;
	BOOLEAN race;

	UNREFERENCED_PARAMETER(FltObjects);

	PAGED_CODE();

	//DbgPrint("SfPreSetInfoCallback: entered\n");

	switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
	case FileDispositionInformation:
		status = SfGetOrSetContext(FltObjects, 
								   Data->Iopb->TargetFileObject, 
								   (PFLT_CONTEXT*)&streamContext);
		if(!NT_SUCCESS(status))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;

		race = (InterlockedIncrement(&streamContext->numOps) > 1);  //interlocked functions perform
																	//atomic operations (one hit)
		if(!race)
		{
			*CompletionContext = (PVOID)streamContext;
			return FLT_PREOP_SYNCHRONIZE;
		}
		else
			FltReleaseContext(streamContext);

	default:
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
}


FLT_POSTOP_CALLBACK_STATUS
SfPostSetInfoCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	)
{
	PSF_STREAM_CONTEXT streamContext;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	//DbgPrint("SfPostSetInfoCallback: entered\n");

	ASSERT(Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation);
	ASSERT(CompletionContext != NULL);

	streamContext = (PSF_STREAM_CONTEXT)CompletionContext;

	if(NT_SUCCESS(Data->IoStatus.Status))
		streamContext->setDisp = ((PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile;
	
	InterlockedDecrement(&streamContext->numOps);
	FltReleaseContext(streamContext);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
SfPreCleanupCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	)
{
	PSF_STREAM_CONTEXT streamContext;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);

	PAGED_CODE();

	//DbgPrint("SfPreCleanupCallback: entered\n");

	status = FltGetStreamContext( Data->Iopb->TargetInstance,
                                  Data->Iopb->TargetFileObject,
                                  (PFLT_CONTEXT*)&streamContext );

	if(NT_SUCCESS(status))
	{
		status = SfGetFileNameInformation(Data, streamContext);
		
		if(NT_SUCCESS(status))
		{
			*CompletionContext = (PVOID)streamContext;
			return FLT_PREOP_SYNCHRONIZE;
		}
		else
			FltReleaseContext(streamContext);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
SfPostCleanupCallback(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	)
{
	FILE_STANDARD_INFORMATION fileInfo;
	PSF_STREAM_CONTEXT streamContext = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	//DbgPrint("SfPostCleanupCallback: entered\n");

	//when driver instance being torn, fltmgr performs draining (preop done, postop awaited)
	//[postop called even if i/o incomplete and flag set]
	ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
	ASSERT(CompletionContext != NULL);

	streamContext = (PSF_STREAM_CONTEXT)CompletionContext;

	if (NT_SUCCESS( Data->IoStatus.Status )) 
	{
		if(((streamContext->numOps >= 0) || (streamContext->setDisp) || 
			(streamContext->deleteOnClose)) && (streamContext->isNotified == 0))
		{
			status = FltQueryInformationFile(Data->Iopb->TargetInstance,
				                             Data->Iopb->TargetFileObject,
					                         &fileInfo,
						                     sizeof(fileInfo),
							                 FileStandardInformation,
								             NULL);
			if(status == STATUS_FILE_DELETED)
			{
				status = SfProcessDelete(Data,
										 FltObjects,
										 streamContext);
				if(!NT_SUCCESS(status))
					DbgPrint("Unable to verify delete\n");
			}
		}
	}

	FltReleaseContext(streamContext);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Misc. helper functions													   //
/////////////////////////////////////////////////////////////////////////////////

NTSTATUS
SfGetFileNameInformation(
	__in PFLT_CALLBACK_DATA Data,
	__inout PSF_STREAM_CONTEXT StreamContext
	)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION newNameInfo;
	PFLT_FILE_NAME_INFORMATION oldNameInfo;

	PAGED_CODE();

	//DbgPrint("SfGetFileNameInformation: entered\n");

	status = FltGetFileNameInformation(Data,
									   FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT,
									   &newNameInfo);
	if(!NT_SUCCESS(status))
		return status;
	
	status = FltParseFileNameInformation(newNameInfo);

	if(!NT_SUCCESS(status))
		return status;

	oldNameInfo = (PFLT_FILE_NAME_INFORMATION)InterlockedExchangePointer(&StreamContext->nameInfo,
																		 newNameInfo);
	if(oldNameInfo != NULL)
		FltReleaseFileNameInformation(oldNameInfo);

	return status;
}


NTSTATUS
SfAllocateUnicodeString(
	__inout PUNICODE_STRING String
	)
{
	PAGED_CODE();

	//DbgPrint("SfAllocateUnicodeString: entered\n");

	ASSERT(String != NULL);
	ASSERT(String->MaximumLength != 0);

	String->Length = 0;
	String->Buffer = (PWCH)ExAllocatePoolWithTag(SF_CONTEXT_POOL_TYPE,
												 String->MaximumLength,
												 SF_STRING_POOL_TAG);
	if(String->Buffer == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	
	return STATUS_SUCCESS;
}


VOID
SfFreeUnicodeString(
	__inout PUNICODE_STRING String
	)
{
	PAGED_CODE();

	//DbgPrint("SfFreeUnicodeString: entered\n");

	ASSERT(String != NULL);
	ASSERT(String->MaximumLength != 0);

	String->Length = 0;

	if(String->Buffer != NULL)
	{
		String->MaximumLength = 0;
		ExFreePool(String->Buffer);
		String->Buffer = NULL;
	}
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Deletion processing callbacks											   //
/////////////////////////////////////////////////////////////////////////////////

NTSTATUS
SfIsFileDeleted(
	__in PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects
	)
{
	NTSTATUS status;
	FILE_OBJECTID_BUFFER fileObjectIdBuf;

	PAGED_CODE();

	DbgPrint("SfIsFileDeleted: entered\n");
	
	status = FltFsControlFile(Data->Iopb->TargetInstance,
							  Data->Iopb->TargetFileObject,
							  FSCTL_GET_OBJECT_ID,
							  NULL,
							  0,
							  &fileObjectIdBuf,
							  sizeof(FILE_OBJECTID_BUFFER),
							  NULL);
	switch(status) {
	
		case STATUS_OBJECTID_NOT_FOUND:
			return STATUS_SUCCESS;
		default:
			NOTHING;
	}

	return status;
}


NTSTATUS
SfProcessDelete(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PSF_STREAM_CONTEXT StreamContext
	)
{
	NTSTATUS status;
	BOOLEAN isFileDeleted = FALSE;
	
	PAGED_CODE();

	DbgPrint("SfProcessDelete: entered\n");

	status = SfIsFileDeleted(Data,
							 FltObjects);

	if(status == STATUS_FILE_DELETED)
	{
		if(InterlockedIncrement(&StreamContext->isNotified) <= 1)
			DbgPrint("A file \"%wZ\" has been deleted\n", &StreamContext->nameInfo->Name);
		status = STATUS_SUCCESS;
	}

	return status;
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Context manipulation callback											   //
/////////////////////////////////////////////////////////////////////////////////

NTSTATUS
SfGetOrSetContext(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PVOID Target,
	__inout_opt PFLT_CONTEXT *Context
	)
{
	NTSTATUS status;
	PFLT_CONTEXT newContext;
	PFLT_CONTEXT oldContext;

	PAGED_CODE();

	//DbgPrint("SfGetOrSetContext: entered\n");

	ASSERT(Context != NULL);

	newContext = *Context;

	status = FltGetStreamContext(FltObjects->Instance,
								 (PFILE_OBJECT)Target,
								 &oldContext);
	if(status == STATUS_NOT_FOUND)
	{
		if(newContext == NULL)
		{
			status = FltAllocateContext(SfData.FilterHandle,
										FLT_STREAM_CONTEXT,
										sizeof(SF_STREAM_CONTEXT),
										SF_CONTEXT_POOL_TYPE,
										&newContext);
			if(NT_SUCCESS(status))
				RtlZeroMemory(newContext, sizeof(SF_STREAM_CONTEXT));
			else
				return status;
		}
	}
	else if(!NT_SUCCESS(status))
		return status;
	else
	{
		ASSERT(newContext != oldContext);

		if(newContext != NULL)
			FltReleaseContext(newContext);

		*Context = oldContext;
		
		return status;
	}

	status = FltSetStreamContext(FltObjects->Instance,
								 (PFILE_OBJECT)Target,
								 FLT_SET_CONTEXT_KEEP_IF_EXISTS,
								 newContext,
								 &oldContext);
	if(!NT_SUCCESS(status))
	{
		FltReleaseContext(newContext);

		if(status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
		{
			*Context = oldContext;
			return STATUS_SUCCESS;
		}
		else
		{
			*Context = NULL;
			return status;
		}
	}

	*Context = newContext;
	return status;
}

/////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////
//  Context cleanup callback												   //
/////////////////////////////////////////////////////////////////////////////////

VOID
SfStreamContextCleanupCallback(
	__in PSF_STREAM_CONTEXT streamContext,
	__in FLT_CONTEXT_TYPE ContextType
	)
{
	UNREFERENCED_PARAMETER(ContextType);

	PAGED_CODE();

	DbgPrint("SfStreamContextCleanupCallback: entered\n");

	ASSERT(ContextType == FLT_STREAM_CONTEXT);

	if(streamContext->nameInfo != NULL)
	{
		FltReleaseFileNameInformation(streamContext->nameInfo);
		streamContext->nameInfo = NULL;
	}
}

/////////////////////////////////////////////////////////////////////////////////