#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

mod binds;
use binds::*;

#[no_mangle]
#[panic_handler]
#[inline(always)]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

type LoadLibraryAFn = extern "system" fn(lpFileName: LPCSTR) -> PVOID;
type GetProcAddressFn = extern "system" fn(hmodule: PVOID, name: LPCSTR) -> PVOID;


const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_THREAD_ATTACH: DWORD = 2;
const DLL_THREAD_DETACH: DWORD = 3;
const DLL_PROCESS_DETACH: DWORD = 0;

#[repr(C)]
pub struct ShellcodeParams {
    load_library: LoadLibraryAFn,
    get_proc_address: GetProcAddressFn,
    dll_base: u64,
    entrypoint: IMAGE_TLS_CALLBACK,
    done: u64,
}

#[no_mangle]
 pub unsafe extern "C" fn main(params: &mut ShellcodeParams) {
    let dll_base =  params.dll_base ;
    let raw_image = dll_base as *mut u8;
    let dos_header: *mut IMAGE_DOS_HEADER = raw_image as *mut IMAGE_DOS_HEADER;
    
    let load_library = params.load_library;
    let get_proc_address = params.get_proc_address;
    let entrypoint = params.entrypoint;


    let opt_hdr: &IMAGE_NT_HEADERS64 = core::mem::transmute(raw_image as usize +  (*dos_header).e_lfanew as usize);

    let location_delta = raw_image as usize - opt_hdr.OptionalHeader.ImageBase as usize ;
    if location_delta != 0 {
        let reloc_dir = &opt_hdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_INDEX::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.Size == 0 {
            return
        }
        let reloc_dir = IMAGE_DATA_DIRECTORY_WRAPPER {
            directory: core::mem::transmute(raw_image as usize + reloc_dir.VirtualAddress as usize)
        };
        for reloc in reloc_dir {
            let reloc_addr = reloc.VirtualAddress as usize;
            for entry in reloc {
                if (entry >> 0x0C) == IMAGE_REL_BASED_DIR64 {
                    let pPatch = (raw_image as usize + reloc_addr + (entry & 0xFFF) as usize) as *mut usize;
                    (*pPatch) += location_delta;
                }
            }
        }
    }

    let import_directory = &opt_hdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_INDEX::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_directory.Size != 0 {
        let import_directory = IMAGE_IMPORT_DIRECTORY_WRAPPER {
            import_desc: (raw_image as usize + import_directory.VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR
        };
        for import in import_directory {
            let module_name = (raw_image as usize + (*import).Name as usize) as *const i8;
            let handle_dll = load_library(module_name) as HANDLE;
            let thunk = (raw_image as usize + (*import).OriginalFirstThunk as usize) as *mut usize;
            let func = (raw_image as usize + (*import).FirstThunk as usize) as *mut usize;

            let imported_functions = IMPORT_FUNCTION_WRAPPER {
                thunk: match thunk as usize {
                    0 => func,
                    _ => thunk
                },
                func: func
            };
            for (thunk, func) in imported_functions {
                // Image snap by ordinal
                let IMAGE_ORDINAL_FLAG64: usize = 0x8000000000000000;
                *func = match thunk & IMAGE_ORDINAL_FLAG64 {
                    0 => {
                        let import = raw_image as usize + thunk;
                        get_proc_address(handle_dll , (import + 2) as LPCSTR) as usize
                    },
                    _ => { get_proc_address(handle_dll , (thunk & 0xFFFF) as LPCSTR) as usize }
                };
            }
        }
    }

    let tls = &opt_hdr.OptionalHeader.DataDirectory[(IMAGE_DIRECTORY_ENTRY_INDEX::IMAGE_DIRECTORY_ENTRY_TLS) as usize];
    if tls.Size != 0{
        let tls = IMAGE_TLS_DIRECTORY_WRAPPER {
            tls: (raw_image as usize + tls.VirtualAddress as usize) as *mut IMAGE_TLS_DIRECTORY
        };
        for callback in tls {
            (*callback)(dll_base as *mut binds::c_void, DLL_PROCESS_ATTACH, 0 as *mut binds::c_void);
        }
    }
    entrypoint(dll_base as *mut binds::c_void, DLL_PROCESS_ATTACH, 0 as *mut binds::c_void);
    params.done = 1;
}

