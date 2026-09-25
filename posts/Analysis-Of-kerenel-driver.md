---
title:  Analysis of vulnerable kernel driver
tags : Reverse , Malware Analysis
categories:
  - Real World
---
<!-- more -->



##  Analysis of a vulnerable kernel driver (CVE-2025-68947)
### [malware_sample](https://malops.io/challenges/kernel-shield)

### Before reading :  [best kernel intro](https://blog.talosintelligence.com/exploring-malicious-windows-drivers-part-1-introduction-to-the-kernel-and-drivers/)  ,    [some sources](https://cymulate.com/blog/defending-against-bring-your-own-vulnerable-driver-byovd-attacks/)    ,    [also this](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-kernel-drivers-101)    ,    [Internal explain](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals)

### Overview : 
A vulnerability in the NSecsoft's NSecKrnl Windows kernel driver allows a local attacker to terminate arbitrary processes — including those owned by SYSTEM and Protected Process Light (PPL) targets — without requiring elevated trust. By leveraging a Bring Your Own Vulnerable Driver (BYOVD) technique, an attacker can exploit this flaw to disable endpoint security solutions and critical system processes, effectively achieving defense evasion and process control at the kernel level.

### 	<ins> Basic Static Analysis	</ins> 
### First start with DIE ( Detect It Easy )
![](/images/die.png "DIE")
#### As you see that this is a PE driver written in C lang 

#### Now using PEStudio for more PE info 
sha256 : 206F27AE820783B7755BCA89F83A0FE096DBB510018DD65B63FC80BD20C03261
PDB file name : NSecKrnl64.pdb
Original File Name : NSecKrnl
Compilation time : Mon Apr 27 08:13:11 2020 (UTC)
![](/images/Red_flag.png "Red Flags")

#### As you see there is many red flag imports 
#### Strings Time 
![](/images/strings.png "strings")
#### In the green line we have a value that maybe a parameter for a API ,While other red lines is same as we got from PE 
### 	<ins>  Advance Static Analysis (IDA)	</ins> 
### Start from the Driver Entry then the function with DriverObject as parameter 
```C
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  _security_init_cookie();
  return sub_14000114C(DriverObject);
}
```
### Also as **[Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object)**

```C
NTSTATUS DriverEntry(
  _In_ PDRIVER_OBJECT  DriverObject,
  _In_ PUNICODE_STRING RegistryPath
);
```
#### Analysis of function sub_14000114C
```C
NTSTATUS __fastcall sub_14000114C(PDRIVER_OBJECT DriverObject)
{
  NTSTATUS result; // eax
  NTSTATUS v3; // ebx
  struct _UNICODE_STRING DestinationString; // [rsp+40h] [rbp-28h] BYREF
  struct _UNICODE_STRING SymbolicLinkName; // [rsp+50h] [rbp-18h] BYREF
  PDEVICE_OBJECT DeviceObject; // [rsp+70h] [rbp+8h] BYREF

  *((_DWORD *)DriverObject->DriverSection + 26) |= 0x20u;
  SpinLock = 0;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\NSecKrnl");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\NSecKrnl");
  DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_140001030;
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;
  result = IoCreateDevice(DriverObject, 0, &DestinationString, 0x22u, 0, 0, &DeviceObject);
  if ( result >= 0 )
  {
    v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
    if ( v3 >= 0 )
    {
      byte_140003010 = PsSetCreateProcessNotifyRoutine(NotifyRoutine, 0) >= 0;
      byte_140003011 = PsSetLoadImageNotifyRoutine(guard_check_icall_nop) >= 0;
      sub_140001518();
    }
    else
    {
      IoDeleteDevice(DeviceObject);
    }
    return v3;
  }
  return result;
}
```
NSecKrnl -> is the vuln driver 

From the first line in the code we see that there is an oring of Driversection with 0x20 , and drivers should not access it based on micorsoft , And this is used for bypass a kernel security check , more here **[LDR_DRIVERSECTION](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry/index.htm)**
 
how to map it to flags ? (20) 0x1A  \* 4 ( as bytes )  = 0x68 which point to flags then oring with 0x20 , 0x20 point to ProcessStaticImport  which is loader bookkeeping flag **[kerenl_flags_ldr](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry/flags.htm)**

```c 
 RtlInitUnicodeString(&DestinationString, L"\\Device\\NSecKrnl");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\NSecKrnl");
```
SymbolicLinkName Which it used to make user-mode user to interact with files in kernel driver object, so he is creating it to interact with the kerenl driver object  ( The symbolic link allows user-mode applications to communicate with the device via CreateFile and DeviceIoControl )
  ```C
   DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001010;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_140001030;
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400010E0;
  ```
And now we have a MajorFunctions : is an array of function pointers which work as dispatcher and based on **[this](https://www.aldeid.com/wiki/DRIVER_OBJECT)** each index functionality 
 
 0 -> Called when user-mode opens the device (CreateFile) 
 
 2 -> Called when user-mode closes the handle (CloseHandle) 
 
 14 -> Called when user-mode sends IOCTL (DeviceIoControl) 
 
#### let's see MajorFunction[14] which is `sub_140001030`

```C
__int64 __fastcall sub_140001030(__int64 a1, IRP *Irp)
{
  struct _IRP *MasterIrp; // r9
  unsigned int Status; // edi
  char v5; // al

  MasterIrp = Irp->AssociatedIrp.MasterIrp;
  Status = -1073741823;
  if ( Irp->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 2246868 )
  {
    if ( MasterIrp && (unsigned __int8)sub_1400012B8(*(_QWORD *)&MasterIrp->Type) )
      Status = 0;
  }
  else
  {
    if ( Irp->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 2246872 )
    {
      if ( !MasterIrp )
        goto LABEL_16;
      v5 = sub_140001614(*(_QWORD *)&MasterIrp->Type);
    }
    else if ( Irp->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 2246876 )
    {
      if ( !MasterIrp )
        goto LABEL_16;
      v5 = sub_140001240(*(_QWORD *)&MasterIrp->Type);
    }
    else
    {
      if ( Irp->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart != 2246880 || !MasterIrp )
        goto LABEL_16;
      v5 = sub_1400013E8(*(_QWORD *)&MasterIrp->Type);
    }
    if ( v5 )
      Status = 0;
  }
LABEL_16:
  Irp->IoStatus.Status = Status;
  IofCompleteRequest(Irp, 0);
  return Status;
}
```

There is a MasterIRP : A pointer used when the driver splits one request into multiple requests , split based on value and maybe a value contain a functionality 
#### MasterIRP is stored in **[IRP structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp)**

`Tail.Overlay.CurrentStackLocation` -> this store description about the request 

`Parameters.Read.ByteOffset.LowPart` -> read ( but we are in control ) the low bytes offset 32-bit to check the commmand it handle as follow  insted of reading `Parameters.DeviceIoControl.IoControlCode` it reads `Parameters.Read.ByteOffset.LowPart` which contain the same commands 


> The driver trusts a pointer taken from the IRP (Irp->AssociatedIrp.MasterIrp) and interprets data from it as a process identifier without validating the requestor’s privileges or the origin of the data. This allows a low-privileged user to supply controlled input that the kernel driver uses to perform privileged operations (e.g terminating arbitrary processes). This missing authorization and improper trust of user-controlled data is the root cause of the CVE.

#### It should have something to check the privilege of the caller, something like this:

```c
if (!SeSinglePrivilegeCheck(SeDebugPrivilege, UserMode))
    return STATUS_ACCESS_DENIED;
```

```c
char __fastcall sub_1400013E8(void *ProcessId)
{
    HANDLE ProcessHandle;   // [rsp+58h] [rbp+10h] BYREF
    PEPROCESS Process;      // [rsp+60h] [rbp+18h] BYREF

    Process = 0;
    ProcessHandle = 0;

    if (PsLookupProcessByProcessId(ProcessId, &Process) >= 0 &&
        ObOpenObjectByPointer(Process, 0x200u, 0, 1u,
                              PsProcessType, 0, &ProcessHandle) >= 0)
    {
        ZwTerminateProcess(ProcessHandle, 0);
        ZwClose(ProcessHandle);
    }

    if (Process)
        ObfDereferenceObject(Process);

    return 0;
}
```

if we focused on the `0x2248E0` code function we see that this is a termination function so this where the attacker terminate the processes 
`PsLookupProcessByProcessId` - > Converts a PID to a kernel process object (PEPROCESS) to target the kerenl structre of the process 

`ObOpenObjectByPointer` - > Opens a kernel handle to the target process with PROCESS_TERMINATE rights (0x200) ,  and returns a handle to the object.

`ZwTerminateProcess` - > terminate the process from its roots 

`ObfDereferenceObject` - > dereference the pointer for cleanup


| IOCTL (hex) | Function        | Purpose                                | Behavior                                                                 |
|-------------|---------------- |----------------------------------------|--------------------------------------------------------------------------|
| 0x224814    | sub_1400012B8   | Register Process ID in Protected List  | Adds a process to the protected list (`qword_140003030`).                |
| 0x224818    | sub_140001614   | Remove Process ID from Protected List  | Removes/clears a process entry from the protected list.                  |
| 0x22481C    | sub_140001240   | Check process against Protected List   | Tracks active/protected resources                                        |
| 0x224820    | sub_1400013E8   | Terminate Process                      | Terminates the specified process by PID.                                 |

The vulnerability allows a local, low-privileged user to terminate arbitrary processes, including those running as SYSTEM. The driver accepts crafted requests from user-mode and performs the requested operation in kernel context without validating the caller’s privileges. Because the termination occurs in kernel mode, normal Windows process protection boundaries are bypassed.


> And in the `DriverObject->DriverUnload` performs any operations that are necessary before the system unloads the driver , so basically doing unload for the driver  
### Function sub_1400012B8 and other commands function 
 The function first acquires a spinlock to prevent concurrent access to the global list, then checks if `MasterIrp->Type` is already registered by another thread. If not, it inserts the value into the list to mark it as in use, then releases the spinlock and returns 1 to indicate the value is now active. **[Spin Lock](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-spin-locks)**
 
 If none of the hidden command checks succeed, or if the value is invalid, the driver returns STATUS_UNSUCCESSFUL (0xC0000001) to indicate failure.
 
 The vulnerable driver then create a device object using the `DestinationString` as name and type as 0x22 (FILE_DEVICE_UNKNOWN) 
 > `FILE_DEVICE_UNKNOWN`-> indicate that the driver is a custom or unknown device type
 
And after the creation of the device object without error..

Symbolic Link Creation: After the device object is created, a symbolic link is established. This allows user-mode applications to interact with the driver through a path like `\\??\\MyDevice`. [source](https://medium.com/@s12deff/step-into-kernel-development-your-first-driver-031c8472ab02)

`PsSetCreateProcessNotifyRoutine` -> The PsSetCreateProcessNotifyRoutine routine adds a driver-supplied callback routine to, or removes it from, a list of routines to be called whenever a process is created or deleted.


```C
void __fastcall NotifyRoutine(HANDLE ParentId, __int64 ProcessId, BOOLEAN Create)
{
  if ( !Create )  -> here is for not creation ( termination ) 
  {
    sub_140001614(ProcessId); -> clean up 
    sub_1400015B4(ProcessId); -> clean up 
  }
}
```
`PsSetLoadImageNotifyRoutine` -> this called whenever image loaded (.exe,.dll) while `PsSetCreateProcessNotifyRoutine` called whenever a process is created or deleted.
#### Analysis of function sub_140001518
```C
NTSTATUS sub_140001518()
{
  NTSTATUS result; // eax
  PVOID RegistrationHandle; // rcx
  _QWORD OperationRegistration[4]; // [rsp+20h] [rbp-50h] BYREF
  _OB_CALLBACK_REGISTRATION CallbackRegistration; // [rsp+40h] [rbp-30h] BYREF

  OperationRegistration[0] = PsProcessType;
  OperationRegistration[1] = 3;
  OperationRegistration[2] = sub_1400014B0;
  memset(&CallbackRegistration, 0, sizeof(CallbackRegistration));
  OperationRegistration[3] = 0;
  *&CallbackRegistration.Version = 65792;
  RtlInitUnicodeString(&CallbackRegistration.Altitude, L"328987");
  CallbackRegistration.RegistrationContext = 0;
  CallbackRegistration.OperationRegistration = OperationRegistration;
  result = ObRegisterCallbacks(&CallbackRegistration, &RegistrationHandle);
  RegistrationHandle = RegistrationHandle;
  if ( result < 0 )
    RegistrationHandle = 0;
  RegistrationHandle = RegistrationHandle;
  return result;
}
```
So this create a CallbackRegistration , and its contain many parts `version , context  , altitude and OperationRegistration` [more_information_here](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration)

And for `OperationRegistration`
```C
typedef struct _OB_OPERATION_REGISTRATION {
  POBJECT_TYPE                *ObjectType; - > PsProcessType
  OB_OPERATION                Operations; - >  3 which is OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE both 
  POB_PRE_OPERATION_CALLBACK  PreOperation; - > and here is the function sub_1400014B0
  POB_POST_OPERATION_CALLBACK PostOperation; -> and nothing after ( post )  the opreations just before ( pre )
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;
```
#### Analysis of function sub_1400014B0
```C 
__int64 __fastcall sub_1400014B0(__int64 a1, __int64 a2)
{
  struct _KPROCESS *Process; // rdi
  HANDLE ProcessId; // rax
  HANDLE CurrentProcessId; // rax

  if ( a2 )
  {
    Process = *(a2 + 8);
    if ( Process )
    {
      if ( *(a2 + 32) )
      {
        if ( IoGetCurrentProcess() != Process )
        {
          ProcessId = PsGetProcessId(Process);
          if ( sub_14000138C(ProcessId) )
          {
            CurrentProcessId = PsGetCurrentProcessId();
            if ( !sub_140001330(CurrentProcessId) )
              **(a2 + 32) &= ~1u;
          }
        }
      }
    }
  }
  return 0;
}
```

```C
char __fastcall sub_14000138C(__int64 ProcessId)
{
  char v2; // bl
  unsigned int n0x400; // edx
  _QWORD *v4; // rax
  struct _KLOCK_QUEUE_HANDLE LockHandle; // [rsp+20h] [rbp-28h] BYREF

  v2 = 0;
  KeAcquireInStackQueuedSpinLock(&SpinLock, &LockHandle);
  n0x400 = 0;
  v4 = qword_140003030;
  while ( ProcessId != *v4 )
  {
    ++n0x400;
    ++v4;
    if ( n0x400 >= 0x400 )
      goto LABEL_6;
  }
  v2 = 1;
LABEL_6:
  KeReleaseInStackQueuedSpinLock(&LockHandle);
  return v2;
}
```
```C
char __fastcall sub_140001330(__int64 CurrentProcessId)
{
  char v2; // bl
  unsigned int n0x400; // edx
  _QWORD *v4; // rax
  struct _KLOCK_QUEUE_HANDLE LockHandle; // [rsp+20h] [rbp-28h] BYREF

  v2 = 0;
  KeAcquireInStackQueuedSpinLock(&SpinLock, &LockHandle);
  n0x400 = 0;
  v4 = qword_140005030;
  while ( CurrentProcessId != *v4 )
  {
    ++n0x400;
    ++v4;
    if ( n0x400 >= 0x400 )
      goto LABEL_6;
  }
  v2 = 1;
LABEL_6:
  KeReleaseInStackQueuedSpinLock(&LockHandle);
  return v2;
}
```

Here first retrive the process from structure in a2 which is [`OB_PRE_OPERATION_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information)

First  ( IoGetCurrentProcess ) - > ensures the requester is not the same as the target.

Then  ( PsGetProcessId ) - > Checks if the target process (ProcessId) is in the `qword_140003030` list , basically its protected process list 

Then  ( PsGetCurrentProcessId ) - > Checks If the requesting process is not in the allowed list

#### Summary 
The vulnerable driver exposes privileged operations to user-mode without proper authorization checks. An unprivileged user can terminate arbitrary processes in kernel mode, bypassing normal Windows process protections.

This fits the "Bring Your Own Vulnerable Driver" model, where attackers load signed but vulnerable drivers to disable security software or manipulate kernel state.

#### To make everything clear ( Steps of how it terminate the processes )
-> Opens the device (allowed to normal users)

-> Sends crafted IRP

-> Supplies target process info

-> Driver performs privileged action

-> No privilege check = action succeeds - > which can terminate processes then 
### IoCs
- **Device Name**: \Device\NSecKrnl
- **Symbolic Link**: \DosDevices\NSecKrnl
- **PDB String**: NSecKrnl64.pdb
- **Callback Altitude**: "328987"
- **IOCTL Range**: 0x224814 - 0x224820
- **sha256** : 206F27AE820783B7755BCA89F83A0FE096DBB510018DD65B63FC80BD20C03261


Thanks for reading <3 