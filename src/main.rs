use core::ffi::c_void;
use clap::Parser;
use std::fs;
use std::slice;
use pelite::pe::{Pe, PeView, PeFile};
use pelite::Pod;
use pelite::FileMap;
use widestring::U16CString;

use windows::{
    core::*,
    Win32::Foundation::*, Win32::System::Threading::*,
    Win32::System::Memory::*, Win32::System::Diagnostics::Debug::*,
    Win32::System::LibraryLoader::*, Win32::Foundation::HINSTANCE,
};

struct ShellcodeParams {
    load_library: u64,
    get_proc_address: u64,
    dll_base: u64,
    done: u64,
}

impl From<*mut c_void> for ShellcodeParams {
    fn from(mut ptr: *mut c_void) -> Self {
        let bytes = ptr.as_bytes_mut();
        ShellcodeParams{
            load_library: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            get_proc_address: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            dll_base: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            done: 0,
        }
    }
}

/*
#[no_mangle]
#[inline(always)]
pub unsafe extern "system" fn shellcode(parameters: *mut c_void) -> u32{

    let parameters = ShellcodeParams::from(parameters);

    let dll_base = parameters.dll_base;

    let raw_image = dll_base as *mut u8;

    let slice = unsafe { slice::from_raw_parts_mut(raw_image, parameters.dll_size) };
    let dll = match PeView::from_bytes(&slice) {
        Ok(o) => o,
        Err(_) => return 1
    };
    let dll_opt_hdr = dll.optional_header();

    let _dll_main = dll_opt_hdr.AddressOfEntryPoint;
    let location_delta = dll_base - dll_opt_hdr.ImageBase;
    if location_delta != 0 {

        // Handle Dir64 relocations
        let base_relocs = match dll.base_relocs() {
            Ok(o) => o,
            Err(_) => return 1,
        };
        base_relocs.for_each(|rva, ty| {
            if ty == 10 {
                let p = raw_image.offset(rva as isize) as *mut usize;
                let fixed_addr = std::ptr::read_unaligned(p).wrapping_add(location_delta as usize);
                std::ptr::write_unaligned(p, fixed_addr);
            }
        })
    }

	// Access the import directory
	let imports = dll.imports().unwrap();

	// Iterate over the import descriptors
	for desc in imports {
		// DLL being imported from
		let dll_name = desc.dll_name().unwrap();

		// Import Address Table and Import Name Table for this imported DLL
		let iat = desc.iat().unwrap();
		let int = desc.int().unwrap();
        
		// Iterate over the imported functions from this DLL
		for (va, import) in Iterator::zip(iat, int) {
        }
	}

    0
}
*/

struct CoffFileHeader {
    f_magic: u16,	/* Magic number */	
	f_nscns: u16,	/* Number of Sections */
	f_timdat: u32,	/* Time & date stamp */
	f_symptr: u32,	/* File pointer to Symbol Table */
	f_nsyms: u32,	/* Number of Symbols */
	f_opthdr: u16,	/* sizeof(Optional Header) */
	f_flags: u16	/* Flags */
}

impl From<&Vec<u8>> for CoffFileHeader {
    fn from(file: &Vec<u8>) -> Self {
        CoffFileHeader{
            f_magic: u16::from_le_bytes(file[0..2].try_into().unwrap()),	/* Magic number */	
            f_nscns: u16::from_le_bytes(file[2..4].try_into().unwrap()),	/* Number of Sections */
            f_timdat: u32::from_le_bytes(file[4..8].try_into().unwrap()),	/* Time & date stamp */
            f_symptr: u32::from_le_bytes(file[8..12].try_into().unwrap()),	/* File pointer to Symbol Table */
            f_nsyms: u32::from_le_bytes(file[12..16].try_into().unwrap()),	/* Number of Symbols */
            f_opthdr: u16::from_le_bytes(file[16..18].try_into().unwrap()),	/* sizeof(Optional Header) */
            f_flags: u16::from_le_bytes(file[18..20].try_into().unwrap())	/* Flags */
        }
    }
}

struct SymtabEntry {
	n_name: [u8;8],	/* Symbol Name */
	n_value: u32,	/* Value of Symbol */
	n_scnum: u16,	/* Section Number */
	n_type: u16,		/* Symbol Type */
	n_sclass: u8,	/* Storage Class */
	n_numaux: u8	/* Auxiliary Count */
}

impl From<Vec<u8>> for SymtabEntry {
    fn from(entry: Vec<u8>) -> Self {
        SymtabEntry{
            n_name: entry[0..8].try_into().unwrap(),	/* Symbol Name */
            n_value: u32::from_le_bytes(entry[8..12].try_into().unwrap()),	/* Value of Symbol */
            n_scnum: u16::from_le_bytes(entry[12..14].try_into().unwrap()),	/* Section Number */
            n_type: u16::from_le_bytes(entry[14..16].try_into().unwrap()),		/* Symbol Type */
            n_sclass: entry[16],	/* Storage Class */
            n_numaux: entry[17] /* Auxiliary Count */
        }
    }
}

struct SectionEntry {
	s_name: [u8;8],	/* Section Name */
	s_paddr: u32,	/* Physical Address */
	s_vaddr: u32,	/* Virtual Address */
	s_size: u32,		/* Section Size in Bytes */
	s_scnptr: u32,	/* File offset to the Section data */
	s_relptr: u32,	/* File offset to the Relocation table for this Section */
	s_lnnoptr: u32,	/* File offset to the Line Number table for this Section */
	s_nreloc: u16,	/* Number of Relocation table entries */
	s_nlnno: u16,	/* Number of Line Number table entries */
	s_flags: u32	/* Flags for this section */
}

impl From<Vec<u8>> for SectionEntry {
    fn from(entry: Vec<u8>) -> Self {
        SectionEntry{
            s_name: entry[0..8].try_into().unwrap(),	/* Section Name */
            s_paddr: u32::from_le_bytes(entry[8..12].try_into().unwrap()),	/* Physical Address */
            s_vaddr: u32::from_le_bytes(entry[12..16].try_into().unwrap()),	/* Virtual Address */
            s_size: u32::from_le_bytes(entry[16..20].try_into().unwrap()),		/* Section Size in Bytes */
            s_scnptr: u32::from_le_bytes(entry[20..24].try_into().unwrap()),	/* File offset to the Section data */
            s_relptr: u32::from_le_bytes(entry[24..28].try_into().unwrap()),	/* File offset to the Relocation table for this Section */
            s_lnnoptr: u32::from_le_bytes(entry[28..32].try_into().unwrap()),	/* File offset to the Line Number table for this Section */
            s_nreloc: u16::from_le_bytes(entry[32..34].try_into().unwrap()),	/* Number of Relocation table entries */
            s_nlnno: u16::from_le_bytes(entry[34..36].try_into().unwrap()),	/* Number of Line Number table entries */
            s_flags: u32::from_le_bytes(entry[36..40].try_into().unwrap())	/* Flags for this section */
        }
    }
}

fn parse_coff_for_shellcode(path: String) -> core::result::Result<Vec<u8>, String>{
    println!("I'm parsiiiiiiiiiiiiiiiiiiiiiin");
    // https://wiki.osdev.org/COFF
    let file = match fs::read(path) {
        Ok(f) => f,
        Err(e) => return Err(e.to_string()),
    };

    // If file is smaller than the COFF header and one symbol table entry
    if file.len() < 20 + 18 {
        return Err("File too small".to_string())
    }

    let header = CoffFileHeader::from(&file);

    let mut ptr = header.f_symptr;
    let mut remaining_sym = header.f_nsyms;
    let payload_arr:[u8;8] = [80,97,121,108,111,97,100,0];

    let (section_number, section_index) = loop {
        if remaining_sym == 0 {
            break (0,0)
        }

        // 18 == sizeof symtable entry
        let header = match file.get(ptr as usize..(ptr+18) as usize) {
            Some(v) => SymtabEntry::from(v.to_vec()),
            None => return Err("Payload not found in symbols".to_string())
        };

        // If symbol name is Payload, the type is a function entry point and the class is C_EXT
        //println!("{:?} {} {} {}", header.n_name, header.n_name.eq(&payload_arr), header.n_type, header.n_scnum);
        if header.n_name.eq(&payload_arr) && header.n_type == 0x20 && header.n_sclass == 0x2 {
            break (header.n_scnum, header.n_value)
        }
        remaining_sym -= 1;
        ptr += 18;
    };

    if section_number == 0{
        return Err("Couldn't find a valid entry for symbol Payload".to_string())
    }

    // Go after the COFF header, then after the optional header and to the section_number-th section
    let header = match file.get((20 + header.f_opthdr + 40 * (section_number - 1)) as usize..(20 + header.f_opthdr + 40 * (section_number - 1) + 40) as usize) {
        Some(v) => SectionEntry::from(v.to_vec()),
        None => return Err("Couldn't get the section entry".to_string())
    };

    match file.get((header.s_scnptr + section_index) as usize..(header.s_scnptr + section_index + header.s_size) as usize) {
        Some(v) => Ok(v.to_vec()),
        None => Err("Couldn't get the payload from the section informations".to_string())
    }
}

unsafe fn get_function_address(module: &str, func: &str) -> core::result::Result<*const (), String> {
    let module = module.to_string();

    let module_handle = GetModuleHandleA(PCSTR(module.as_ptr())).ok();
    let result = GetProcAddress(module_handle, PCSTR(func.as_ptr()));
    match result {
        Some(v) => Ok(v as u64 as *const ()),
        None => Err("Couldn't find the address of function".to_string()),
    }
}

fn manual_map(process: windows::Win32::Foundation::HANDLE, dll_vec: Vec<u8>) -> core::result::Result<(), String>{
    println!("Manual Mapiiiiiiiin");

    let dll = match PeView::from_bytes(&dll_vec) {
        Ok(o) => o,
        Err(e) => return Err(e.to_string())
    };

    let dll_opt_hdr = dll.optional_header();

    let target_base: *const c_void = unsafe { std::mem::transmute(dll_opt_hdr.ImageBase) };
    println!("Prefered image base is: {:#x}", target_base as u64);
    let target_base = unsafe { VirtualAllocEx(process, target_base, dll_opt_hdr.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
    let target_base =
        if target_base as u64 == 0 {
            let target_base = unsafe { VirtualAllocEx(process, std::ptr::null(), dll_opt_hdr.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
            if target_base as u64 == 0 {
                return Err("Cannot allocate memory in the process".to_string())
            }
            target_base
        } 
        else {
            target_base
    };

    // Putting the DLL header into the process
    let written = unsafe {
        // Copying needed informations to the dll address space (Header and more, need to calculate the size better)
        let mut size_written = 0;
        WriteProcessMemory(process, target_base, dll_vec.as_ptr() as u64 as *const c_void, 0x1000, &mut size_written).as_bool()

    };
    if !written {
        return Err("Couldn't put informations in the process space".to_string())
    }

    let section_headers = dll.section_headers();

    for section in section_headers.iter() {
        if section.SizeOfRawData > 0 {
            let mut size_written = 0;
            // Big line incoming
            let result = unsafe {
                // Let me cast a vomit inducing spell
                let sliced = &dll_vec[section.PointerToRawData as usize..(section.PointerToRawData + section.SizeOfRawData) as usize];
                WriteProcessMemory(process, (target_base as u64 + section.VirtualAddress as u64) as *const c_void, sliced.as_ptr() as u64 as *const c_void, section.SizeOfRawData as usize, &mut size_written).as_bool()
            };
            if !result {
                unsafe { VirtualFreeEx(process, target_base as *mut c_void, 0, MEM_RELEASE) };
                return Err("Couldn't write section to process".to_string())
            }
        }
    }

    // Getting the address of LoadLibraryA and get GetProcAddress
    let load_library = unsafe { get_function_address("kernel32.dll\0", "LoadLibraryA\0") }?;
    println!("LoadLibrary done");
    let get_proc_address = unsafe { get_function_address("kernel32.dll\0", "GetProcAddress\0") }?;
    

    let params = ShellcodeParams {
        load_library: load_library as u64, // 
        get_proc_address:  get_proc_address as u64, // This get me the rust wrappers
        dll_base: target_base as u64,
        done: 0,
    };

    println!("LL: {:#x}, GPA: {:#x}, DB: {:#x}, Done: {:#x}", params.load_library, params.get_proc_address, params.dll_base, params.done);

    let param_addr = unsafe { VirtualAllocEx(process, std::ptr::null(), dll_opt_hdr.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if param_addr as u64 == 0 {
        return Err("Memory allocation failed".to_string())
    }
    let written = unsafe {
        // Copying needed informations to the dll address space (Keep the dll struct intact)
        let mut size_written = 0;
        WriteProcessMemory(process, param_addr, vec!(params.load_library, params.get_proc_address, params.dll_base, params.done).as_ptr() as u64 as *const c_void, std::mem::size_of::<ShellcodeParams>(), &mut size_written).as_bool()

    };
    if !written {
        return Err("Couldn't put informations in the process space".to_string())
    }

    let shellcode = match parse_coff_for_shellcode("target/src/shellcode/Injection.o".to_string()){
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let shellcode_addr = unsafe { VirtualAllocEx(process, std::ptr::null(), shellcode.len() as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

    println!("Shellcode addr: {:#x}", shellcode_addr as u64);

    let written = unsafe {
        // Copying the shellcode to the dll address space
        let mut size_written = 0;
        WriteProcessMemory(process, shellcode_addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut size_written).as_bool()
    };
    if !written {
        return Err("Couldn't put informations in the process space".to_string())
    }

    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
    let success = unsafe { VirtualProtectEx(process, shellcode_addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect) };
    if !success.as_bool() {
        return Err("Couldn't change the page permissions".to_string())
    }

    let shellcode_func_ptr: unsafe extern "system" fn (*mut c_void) -> u32 = unsafe { std::mem::transmute(shellcode_addr) };
    let mut tid = 0;
    let thread = unsafe { CreateRemoteThread(process, std::ptr::null(), 0, Some(shellcode_func_ptr), param_addr, 0, &mut tid) };

    match thread {
        Ok(t) => { println!("Thread created"); unsafe { CloseHandle(t); };},
        Err(e) => return Err(e.to_string()),
    }

    Ok(())
}

// Need to use core::result::Result to avoid using the windows one
fn reflective_load(_process: windows::Win32::Foundation::HANDLE, _dll: Vec<u8>) -> core::result::Result<(), String>{
    println!("I'm looooooooodin");
    Err("Failed".to_string())
}

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Args {
    /// The pattern to look for
    #[clap(short = 'I', value_parser)]
    pid: u32,
    /// The path to the file to read
    #[clap(short='P', parse(from_os_str))]
    path_to_dll: std::path::PathBuf,
    // Build the shellcode ? 
    #[clap(short = 'B')]
    build: bool,
}

fn main() {
    let args = Args::parse();
    let pid = args.pid;
    let path_to_dll = args.path_to_dll;
    let build = args.build;

    println!("Pid is {}", pid);
    println!("Dll path is {}", path_to_dll.display());
    println!("build is {}", build);

    if build {
    // No fucking taking the infos from the env variables lol sheeee
    // Technically still makes my project be fully rust Right ?
        let _test = cc::Build::new()
        .files(["src/shellcode/Injection.cpp"])
        .cpp(true)
        .out_dir("./target")
        .target("x86_64-pc-windows-msvc")
        .opt_level(3)
        .host("x86_64-pc-windows-msvc")
        .flag("-EHsc")
        .try_compile("shellcode");
    }

    //let result = parse_coff_for_shellcode("./target/Injection.o".to_string()).unwrap();
    //println!("Size: {}", result.len());

    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid).expect("Cannot open process with given PID") };
    println!("Opened process {process:?}");

    let dll = match fs::read(path_to_dll) {
        Ok(file) => file,
        Err(_) => panic!("Cannot read file at dll path")
    };

    //let _result = test(dll);

    match manual_map(process, dll){
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };

    unsafe { CloseHandle(process); };
}
