#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
pub enum c_void {}
pub type BOOLEAN = u8;
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;
pub type ULONG = u32;
pub type LPSTR = *mut i8;

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BOOLEAN,
    pub ReadImageFileExecOptions: BOOLEAN,
    pub BeingDebugged: BOOLEAN,
    pub BitField: BOOLEAN,
    pub Mutant: HANDLE,
    pub ImageBaseAddress: PVOID,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
}
pub type LPCSTR = *const i8;
#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,
    pub Initialized: BOOLEAN,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    // ...
}

pub type PLDR_DATA_TABLE_ENTRY = *const LDR_DATA_TABLE_ENTRY;
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub BaseAddress: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    // ...
}

pub type USHORT = u16;
pub type PWCH = *mut u16;
pub type DWORD = u32;
pub type WORD = u16;
pub type ULONGLONG = u64;
pub type BYTE = u8;
pub type LONG = u32;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWCH,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}
#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: ULONG,
    pub Length: ULONG,
    pub Flags: ULONG,
    pub DebugFlags: ULONG,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: ULONG,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
}

type PULONG = *mut ULONG;
#[repr(C)]
pub struct IO_STATUS_BLOCK {
    _1: IO_STATUS_BLOCK_u,
    _2: PULONG,
}
/// A specialized `Result` type for NT operations.
pub type Result<T> = ::core::result::Result<T, Status>;

/// NT Status code.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum Status {
    success = 0,
    unsuccessful = 0xC0000001,
}

#[repr(C)]
pub union IO_STATUS_BLOCK_u {
    _1: NTSTATUS,
    _2: PVOID,
}
pub type NTSTATUS = Status;
type HMODULE = HINSTANCE;
type HINSTANCE = *mut HINSTANCE__;
pub enum HINSTANCE__ {}
// ====

pub const SIZE_IMAGE_BASE_RELOCATION: u32 = 2 * 4;
pub const SIZE_IMAGE_DATA_DIRECTORY: usize = 2 * 4; // 2 DWORD struct
pub const SIZE_IMAGE_IMPORT_DESCRIPTOR: u32 = 4 * 5;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}

pub struct IMAGE_DATA_DIRECTORY_WRAPPER {
    pub directory: IMAGE_DATA_DIRECTORY,
}

impl Iterator for IMAGE_DATA_DIRECTORY_WRAPPER {
    type Item = IMAGE_DATA_DIRECTORY;

    fn next(&mut self) -> Option<Self::Item> {
        let res:IMAGE_DATA_DIRECTORY  = unsafe { core::mem::transmute(core::ptr::addr_of!(self.directory)) };
        match self.directory.VirtualAddress {
            0 => { 
                self.directory = unsafe { core::mem::transmute(core::ptr::addr_of!(self.directory) as usize + self.directory.Size as usize) };
                Some(res)
            },
            _ => None,
        }
    }
}

pub struct IMAGE_DATA_DIRECTORY_ITERATOR {
    entry_amount: usize,
    index: usize,
    array: usize,
}

impl IntoIterator for IMAGE_DATA_DIRECTORY {
    type Item = u16;
    type IntoIter = IMAGE_DATA_DIRECTORY_ITERATOR;

    fn into_iter(self) -> Self::IntoIter {
        IMAGE_DATA_DIRECTORY_ITERATOR {
            entry_amount: ((self.Size - SIZE_IMAGE_BASE_RELOCATION) / 2)as usize, // divided by sizeof(WORD);
            index: 0,
            array: unsafe { core::ptr::addr_of!(self) as usize + SIZE_IMAGE_DATA_DIRECTORY }
        }
    }
}

impl Iterator for IMAGE_DATA_DIRECTORY_ITERATOR {
    type Item = u16;
    fn next(&mut self) -> Option<Self::Item> {
        match self.index < self.entry_amount {
            true => {
                let res = unsafe { *((self.array + 2 * self.index) as *mut u16) };
                self.index += 1;
                Some(res)
            }
            false => None
        }
    }
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub OriginalFirstThunk: DWORD,
    pub TimeDateStamp: DWORD,                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    pub ForwarderChain: DWORD,                 // -1 if no forwarders
    pub Name: DWORD,
    pub FirstThunk: DWORD,                     // RVA to IAT (if bound this IAT has actual addresses)
}

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: WORD,
    pub Name: WORD
}



pub struct IMAGE_IMPORT_DIRECTORY_WRAPPER {
    pub import_desc: *mut IMAGE_IMPORT_DESCRIPTOR,
}

impl Iterator for IMAGE_IMPORT_DIRECTORY_WRAPPER {
    type Item = *mut IMAGE_IMPORT_DESCRIPTOR;
    fn next(&mut self) -> Option<Self::Item> {
        match unsafe { (*(self.import_desc)).Name } {
            0 => None,
            _ => {
                let res = self.import_desc;
                self.import_desc = (self.import_desc as usize + 0x14) as *mut IMAGE_IMPORT_DESCRIPTOR;
                Some(res)
            }
        }
    }
}

pub struct IMPORT_FUNCTION_WRAPPER {
    pub thunk: *mut usize,
    pub func: *mut usize
}

impl Iterator for IMPORT_FUNCTION_WRAPPER {
    type Item = (usize, *mut usize);
    fn next(&mut self) -> Option<Self::Item> {
        let thunk = unsafe { self.thunk.read() };
        let func = self.func;
        match thunk {
            0 => None,
            _ => {
                self.thunk = (self.thunk as usize + 8) as *mut usize;
                self.func = (self.func as usize + 8) as *mut usize;
                Some((thunk, func))
            }
        }
    }
}

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY {
    pub StartAddressOfRawData: ULONGLONG,
    pub EndAddressOfRawData: ULONGLONG,
    pub AddressOfIndex: ULONGLONG,         // PDWORD
    pub AddressOfCallBacks: ULONGLONG,     // PIMAGE_TLS_CALLBACK *;
    pub SizeOfZeroFill: DWORD,
    pub Characteristics: DWORD
}

pub struct IMAGE_TLS_DIRECTORY_WRAPPER {
    pub tls: *const IMAGE_TLS_DIRECTORY
}

pub type IMAGE_TLS_CALLBACK = extern "system" fn(DllHandle: PVOID, Reason: DWORD, Reserved: PVOID) -> u32;

pub struct IMAGE_TLS_DIRECTORY_ITERATOR {
    callback: *const IMAGE_TLS_CALLBACK
}

impl IntoIterator for IMAGE_TLS_DIRECTORY_WRAPPER {
    type Item = *const IMAGE_TLS_CALLBACK;
    type IntoIter = IMAGE_TLS_DIRECTORY_ITERATOR;

    fn into_iter(self) -> Self::IntoIter {
        IMAGE_TLS_DIRECTORY_ITERATOR {
            callback: unsafe { (*(self.tls)).AddressOfCallBacks as *mut IMAGE_TLS_CALLBACK }
        }
    }
}

impl Iterator for IMAGE_TLS_DIRECTORY_ITERATOR {
    type Item = *const IMAGE_TLS_CALLBACK;
    fn next(&mut self) -> Option<Self::Item> {
        match unsafe { self.callback as usize != 0 && *(self.callback as *mut usize) != 0 } {
            true => { 
                let res = self.callback;
                self.callback = (self.callback as usize + 8) as *const IMAGE_TLS_CALLBACK;
                Some(res)
            },
            false => None
        }
    }
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}
type ULONG_PTR = usize;

pub const IMAGE_DOS_SIGNATURE: WORD = 0x5A4D;

pub type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: ULONGLONG,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONGLONG,
    pub SizeOfStackCommit: ULONGLONG,
    pub SizeOfHeapReserve: ULONGLONG,
    pub SizeOfHeapCommit: ULONGLONG,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum IMAGE_DIRECTORY_ENTRY_INDEX {
    IMAGE_DIRECTORY_ENTRY_EXPORT         = 0,   // Export Directory
    IMAGE_DIRECTORY_ENTRY_IMPORT         = 1,   // Import Directory
    IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2,   // Resource Directory
    IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3,   // Exception Directory
    IMAGE_DIRECTORY_ENTRY_SECURITY       = 4,   // Security Directory
    IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5,   // Base Relocation Table
    IMAGE_DIRECTORY_ENTRY_DEBUG          = 6,   // Debug Directory
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7,   // Architecture Specific Data
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8,   // RVA of GP
    IMAGE_DIRECTORY_ENTRY_TLS            = 9,   // TLS Directory
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10,  // Load Configuration Directory
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11,  // Bound Import Directory in headers
    IMAGE_DIRECTORY_ENTRY_IAT            = 12,   // Import Address Table
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13,   // Delay Load Import Descriptors
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,   // COM Runtime descriptor
}