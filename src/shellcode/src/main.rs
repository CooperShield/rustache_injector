#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

mod binds;
use binds::*;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

type LoadLibraryAFn = extern "system" fn(lpFileName: LPCSTR) -> PVOID;
type GetProcAddressFn = extern "system" fn(hmodule: PVOID, name: LPCSTR) -> PVOID;
type IMAGE_TLS_CALLBACK = extern "system" fn(DllHandle: PVOID, Reason: DWORD, Reserved: PVOID) -> u32;

const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_THREAD_ATTACH: DWORD = 2;
const DLL_THREAD_DETACH: DWORD = 3;
const DLL_PROCESS_DETACH: DWORD = 0;

pub struct ShellcodeParams {
    load_library: LoadLibraryAFn,
    get_proc_address: GetProcAddressFn,
    dll_base: u64,
    done: u64,
}

#[no_mangle]
 pub unsafe extern "C" fn main(params: *mut ShellcodeParams) {
    let dll_base =  (*params).dll_base ;
    let raw_image = dll_base as *mut u8;
    let dos_header: *mut IMAGE_DOS_HEADER = raw_image as *mut IMAGE_DOS_HEADER;
    
    let load_library = (*params).load_library;
    let get_proc_address = (*params).get_proc_address;


    let opt_hdr: *mut IMAGE_NT_HEADERS64 = (raw_image as usize +  (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    let entrypoint = (raw_image as usize + (*opt_hdr).OptionalHeader.AddressOfEntryPoint as usize) as *const IMAGE_TLS_CALLBACK ;

    let location_delta = raw_image as usize - (*opt_hdr).OptionalHeader.ImageBase as usize ;
    if location_delta != 0 {

        let reloc_directory = &(*opt_hdr).OptionalHeader.DataDirectory[(IMAGE_DIRECTORY_ENTRY_INDEX::IMAGE_DIRECTORY_ENTRY_BASERELOC) as usize];
        if reloc_directory.Size == 0 {
            return
        }

        let mut reloc_data: *mut IMAGE_DATA_DIRECTORY = (raw_image as usize + reloc_directory.VirtualAddress as usize) as *mut IMAGE_DATA_DIRECTORY;
        
        while (*reloc_data).VirtualAddress == 0{
            // 
            let AmountOfEntries = ((*reloc_data).Size - SIZE_IMAGE_BASE_RELOCATION) / 2; // divided by sizeof(WORD);\
            let relative_info = (reloc_data as usize + SIZE_IMAGE_DATA_DIRECTORY) as *mut u16; // Go past the IMAGE_DATA_DIRECTORY header
            for _ in 0..AmountOfEntries {
                if (*relative_info >> 0x0C) == IMAGE_REL_BASED_DIR64 {
                    *((raw_image as usize + (*reloc_data).VirtualAddress as usize + ((*relative_info) & 0xFFF) as usize) as *mut u16) += location_delta as u16;
                }
            }
            reloc_data = (reloc_data as usize + (*reloc_data).Size as usize) as *mut IMAGE_DATA_DIRECTORY;
        }
    }
    let import_directory = &(*opt_hdr).OptionalHeader.DataDirectory[(IMAGE_DIRECTORY_ENTRY_INDEX::IMAGE_DIRECTORY_ENTRY_IMPORT) as usize];
    if import_directory.Size != 0 {
        let mut import_desc = (raw_image as usize + import_directory.VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;
        while (*import_desc).Name != 0 {
            let module_name = (raw_image as usize + (*import_desc).Name as usize) as *const i8;

            let handle_dll = load_library(module_name) as *mut c_void;

            let mut thunk = (raw_image as usize + (*import_desc).OriginalFirstThunk as usize) as *mut usize;
            let mut func = (raw_image as usize + (*import_desc).FirstThunk as usize) as *mut usize;
            
            if thunk as usize == 0 {
                thunk = func;
            }
            while *thunk != 0 {
                // Image snap by ordinal
                let IMAGE_ORDINAL_FLAG64: usize = 0x8000000000000000;
                match *thunk & IMAGE_ORDINAL_FLAG64 {
                    0 => {
                        let import = (raw_image as usize + *thunk) as *mut IMAGE_IMPORT_BY_NAME;
                        *func = get_proc_address(handle_dll , (*import).Name) as usize;
                    },
                    _ => { *func = get_proc_address(handle_dll , ((*thunk) & (0xFFFF as usize)) as *const i8) as usize; }
                }
                thunk = (thunk as usize + 8) as *mut usize;
                func = (func as usize + 8) as *mut usize;
            }
            import_desc = (import_desc as usize + SIZE_IMAGE_IMPORT_DESCRIPTOR as usize) as *mut IMAGE_IMPORT_DESCRIPTOR;
        }
    }
    let tls = &(*opt_hdr).OptionalHeader.DataDirectory[(IMAGE_DIRECTORY_ENTRY_INDEX::IMAGE_DIRECTORY_ENTRY_TLS) as usize];
    if tls.Size != 0{
        let tls = (raw_image as usize + tls.VirtualAddress as usize) as *mut IMAGE_TLS_DIRECTORY;
        let mut callback = (*tls).AddressOfCallBacks as *const IMAGE_TLS_CALLBACK;
        while callback as usize != 0 && (*callback) as usize != 0 {
            (*callback)(dll_base as *mut binds::c_void, DLL_PROCESS_ATTACH, 0 as *mut binds::c_void);
            callback = (callback as usize + 8) as *const IMAGE_TLS_CALLBACK;
        }
    }
    (*entrypoint)(dll_base as *mut binds::c_void, DLL_PROCESS_ATTACH, 0 as *mut binds::c_void);
}

