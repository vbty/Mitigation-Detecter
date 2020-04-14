#include "header.h"

INT main(INT argc,PCHAR argv[])
{
	HANDLE ProcHandle;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	CLIENT_ID ClientId = { 0 };
	PROCESS_MITIGATION_POLICY_INFORMATION *RecvBuffer;
	ULONG RecvBufferSize = sizeof(PROCESS_MITIGATION_POLICY_INFORMATION);
	ULONG RetSize;
	NTSTATUS Status;

	if (argc != 2)
	{
		printf("usage:xxx.exe [PID]\n");
		return 0;
	}
	ClientId.UniqueProcess = (HANDLE)atoi(argv[1]);
	Status = NtOpenProcess(
		&ProcHandle,
		PROCESS_QUERY_INFORMATION,
		&ObjAttr,
		&ClientId);
	if (Status < 0)
	{
		printf("NtOpenProcess:%llx\n", Status);
		return 0;
	}

	RecvBuffer = (PROCESS_MITIGATION_POLICY_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RecvBufferSize);

	for (size_t i = ProcessDEPPolicy; i < MaxProcessInfoClass; i++)
	{
		RecvBuffer->Policy = (PROCESS_MITIGATION_POLICY)i;
		
		if (i == ProcessDEPPolicy)
		{
			Status = NtQueryInformationProcess(
				ProcHandle,
				ProcessExecuteFlags,
				RecvBuffer,
				sizeof(ULONG),
				&RetSize);
		}
		else
		{
			Status = NtQueryInformationProcess(
				ProcHandle,
				ProcessMitigationPolicy,
				RecvBuffer,
				RecvBufferSize,
				&RetSize);
		}

		if (Status == 0xC00000BB)
		{
			continue;
		}
		else if (Status < 0)
		{
			printf("NtQueryInformationProcess:%llx\n", Status);
			return 0;
		}

		switch (i)
		{
		case ProcessDEPPolicy:
			puts("\n[*]ProcessDEPPolicy:");
			printf("MEM_EXECUTE_OPTION_DISABLE %d\n",(*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_DISABLE) != 0);
			printf("MEM_EXECUTE_OPTION_ENABLE %d\n", (*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_ENABLE) != 0 );
			printf("MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION %d\n", (*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION) != 0 );
			printf("MEM_EXECUTE_OPTION_PERMANENT %d\n", (*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_PERMANENT) != 0 );
			printf("MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE %d\n", (*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE) != 0 );
			printf("MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE %d\n", (*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE) != 0 );
			printf("MEM_EXECUTE_OPTION_VALID_FLAGS %d\n", (*(PULONG)RecvBuffer & MEM_EXECUTE_OPTION_VALID_FLAGS) != 0 );
			break;
		case ProcessASLRPolicy:
			puts("\n[*]ProcessASLRPolicy:");
			printf("EnableBottomUpRandomization %d\n", RecvBuffer->ASLRPolicy.EnableBottomUpRandomization);
			printf("EnableForceRelocateImages %d\n", RecvBuffer->ASLRPolicy.EnableForceRelocateImages);
			printf("EnableHighEntropy %d\n", RecvBuffer->ASLRPolicy.EnableHighEntropy);
			printf("DisallowStrippedImages %d\n", RecvBuffer->ASLRPolicy.DisallowStrippedImages);
			break;
		case ProcessDynamicCodePolicy:
			puts("\n[*]ProcessDynamicCodePolicy:");
			printf("ProhibitDynamicCode %d\n", RecvBuffer->DynamicCodePolicy.ProhibitDynamicCode);
			printf("AllowThreadOptOut %d\n", RecvBuffer->DynamicCodePolicy.AllowThreadOptOut);
			printf("AllowRemoteDowngrade %d\n", RecvBuffer->DynamicCodePolicy.AllowRemoteDowngrade);
			printf("AuditProhibitDynamicCode %d\n", RecvBuffer->DynamicCodePolicy.AuditProhibitDynamicCode);
			break;
		case ProcessStrictHandleCheckPolicy:
			puts("\n[*]StrictHandleCheckPolicy:");
			printf("RaiseExceptionOnInvalidHandleReference %d\n",RecvBuffer->StrictHandleCheckPolicy.RaiseExceptionOnInvalidHandleReference);
			printf("HandleExceptionsPermanentlyEnabled %d\n", RecvBuffer->StrictHandleCheckPolicy.HandleExceptionsPermanentlyEnabled);
			break;
		case ProcessSystemCallDisablePolicy:
			puts("\n[*]SystemCallDisablePolicy:");
			printf("DisallowWin32kSystemCalls %d\n", RecvBuffer->SystemCallDisablePolicy.DisallowWin32kSystemCalls);
			printf("AuditDisallowWin32kSystemCalls %d\n", RecvBuffer->SystemCallDisablePolicy.AuditDisallowWin32kSystemCalls);
			break;
		case ProcessMitigationOptionsMask:
			break;
		case ProcessExtensionPointDisablePolicy:
			puts("ProcessExtensionPointDisablePolicy:");
			printf("DisableExtensionPoints %d\n", RecvBuffer->ExtensionPointDisablePolicy.DisableExtensionPoints);
			break;
		case ProcessControlFlowGuardPolicy:
			puts("\n[*]ProcessControlFlowGuardPolicy:");
			printf("EnableControlFlowGuard %d\n", RecvBuffer->ControlFlowGuardPolicy.EnableControlFlowGuard);
			printf("EnableExportSuppression %d\n", RecvBuffer->ControlFlowGuardPolicy.EnableExportSuppression);
			printf("StrictMode %d\n", RecvBuffer->ControlFlowGuardPolicy.StrictMode);
			break;
		case ProcessSignaturePolicy:
			puts("\n[*]ProcessSignaturePolicy:");
			printf("MicrosoftSignedOnly %d\n", RecvBuffer->SignaturePolicy.MicrosoftSignedOnly);
			printf("StoreSignedOnly %d\n", RecvBuffer->SignaturePolicy.StoreSignedOnly);
			printf("MitigationOptIn %d\n", RecvBuffer->SignaturePolicy.MitigationOptIn);
			printf("AuditMicrosoftSignedOnly %d\n", RecvBuffer->SignaturePolicy.AuditMicrosoftSignedOnly);
			printf("AuditStoreSignedOnly %d\n", RecvBuffer->SignaturePolicy.AuditStoreSignedOnly);
			break;
		case ProcessFontDisablePolicy:
			puts("\n[*]ProcessFontDisablePolicy:");
			printf("DisableNonSystemFonts %d\n", RecvBuffer->FontDisablePolicy.DisableNonSystemFonts);
			printf("AuditNonSystemFontLoading %d\n", RecvBuffer->FontDisablePolicy.AuditNonSystemFontLoading);
			break;
		case ProcessImageLoadPolicy:
			puts("\n[*]ProcessImageLoadPolicy:");
			printf("NoRemoteImages %d\n", RecvBuffer->ImageLoadPolicy.NoRemoteImages);
			printf("NoLowMandatoryLabelImages %d\n", RecvBuffer->ImageLoadPolicy.NoLowMandatoryLabelImages);
			printf("PreferSystem32Images %d\n", RecvBuffer->ImageLoadPolicy.PreferSystem32Images);
			printf("AuditNoRemoteImages %d\n", RecvBuffer->ImageLoadPolicy.AuditNoRemoteImages);
			printf("AuditNoLowMandatoryLabelImages %d\n", RecvBuffer->ImageLoadPolicy.AuditNoLowMandatoryLabelImages);
			break;
		case ProcessSystemCallFilterPolicy:
			puts("\n[*]SystemCallFilterPolicy:");
			printf("FilterId %d\n", RecvBuffer->SystemCallFilterPolicy.FilterId);
			break;
		case ProcessPayloadRestrictionPolicy:
			RecvBuffer->PayloadRestrictionPolicy;
			puts("\n[*]PayloadRestrictionPolicy:");
			printf("EnableExportAddressFilter %d\n", RecvBuffer->PayloadRestrictionPolicy.EnableExportAddressFilter);
			printf("AuditExportAddressFilter %d\n", RecvBuffer->PayloadRestrictionPolicy.AuditExportAddressFilter);
			printf("EnableExportAddressFilterPlus %d\n", RecvBuffer->PayloadRestrictionPolicy.EnableExportAddressFilterPlus);
			printf("AuditExportAddressFilterPlus %d\n", RecvBuffer->PayloadRestrictionPolicy.AuditExportAddressFilterPlus);
			printf("EnableImportAddressFilter %d\n", RecvBuffer->PayloadRestrictionPolicy.EnableImportAddressFilter);
			printf("AuditImportAddressFilter %d\n", RecvBuffer->PayloadRestrictionPolicy.AuditImportAddressFilter);
			
			printf("\nEnableRopStackPivot %d\n", RecvBuffer->PayloadRestrictionPolicy.EnableRopStackPivot);
			printf("AuditRopStackPivot %d\n", RecvBuffer->PayloadRestrictionPolicy.AuditRopStackPivot);
			
			printf("\nEnableRopCallerCheck %d\n", RecvBuffer->PayloadRestrictionPolicy.EnableRopCallerCheck);
			printf("AuditRopCallerCheck %d\n", RecvBuffer->PayloadRestrictionPolicy.AuditRopCallerCheck);
			
			printf("\nEnableRopSimExec %d\n", RecvBuffer->PayloadRestrictionPolicy.EnableRopSimExec);
			printf("AuditRopSimExec %d\n", RecvBuffer->PayloadRestrictionPolicy.AuditRopSimExec);
			break;
		case ProcessChildProcessPolicy:
			puts("\n[*]ProcessChildProcessPolicy:");
			printf("NoChildProcessCreation %d\n", RecvBuffer->ChildProcessPolicy.NoChildProcessCreation);
			printf("AuditNoChildProcessCreation %d\n", RecvBuffer->ChildProcessPolicy.AuditNoChildProcessCreation);
			printf("AllowSecureProcessCreation %d\n", RecvBuffer->ChildProcessPolicy.AllowSecureProcessCreation);
			break;
		case ProcessSideChannelIsolationPolicy:
			puts("\n[*]ProcessSideChannelIsolationPolicy:");
			printf("SmtBranchTargetIsolation %d\n", RecvBuffer->SideChannelIsolationPolicy.SmtBranchTargetIsolation);
			printf("IsolateSecurityDomain %d\n", RecvBuffer->SideChannelIsolationPolicy.IsolateSecurityDomain);
			printf("DisablePageCombine %d\n", RecvBuffer->SideChannelIsolationPolicy.DisablePageCombine);
			printf("SpeculativeStoreBypassDisable %d\n", RecvBuffer->SideChannelIsolationPolicy.SpeculativeStoreBypassDisable);
			break;
		default:
			break;
		}
	}

}