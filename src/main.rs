use core::ffi::c_void;
use clap::Parser;
use std::fs;
use pelite::pe::{Pe, PeView};

use std::path;

use windows::{
    core::*,
    Win32::Foundation::*, Win32::System::Threading::*,
    Win32::System::Memory::*, Win32::System::Diagnostics::Debug::*,
    Win32::System::LibraryLoader::*,
};

struct ShellcodeParams {
    load_library: u64,
    get_proc_address: u64,
    dll_base: u64,
    entrypoint: u64,
    done: u64,
}

type ShellcodeFn = unsafe extern "system" fn (*mut c_void) -> u32;

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
    // main>
    let payload_symbol:[u8;8] = [109,97,105,110,0,0,0,0];


    let (section_number, section_index) = loop {
        if remaining_sym == 0 {
            break (0,0)
        }

        // 18 == sizeof symtable entry
        let header = match file.get(ptr as usize..(ptr+18) as usize) {
            Some(v) => SymtabEntry::from(v.to_vec()),
            None => return Err("Payload not found in symbols".to_string())
        };

        // If symbol name is main, the type is a function entry point and the class is C_EXT
        if header.n_name.eq(&payload_symbol) && header.n_type == 0x20 && header.n_sclass == 0x2 {
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

fn get_function_address(module: &str, func: &str) -> core::result::Result<*const (), String> {
    let module = module.to_string();

    let module_handle = unsafe { GetModuleHandleA(PCSTR(module.as_ptr())).ok() };
    let result = unsafe { GetProcAddress(module_handle, PCSTR(func.as_ptr())) };
    match result {
        Some(v) => Ok(v as u64 as *const ()),
        None => Err("Couldn't find the address of function".to_string()),
    }
}

fn get_memory(process: HANDLE, addr: *const c_void, size: usize, allocFlags: VIRTUAL_ALLOCATION_TYPE, protectFlag: PAGE_PROTECTION_FLAGS) -> core::result::Result<*mut c_void, String> {
    let addr = unsafe { VirtualAllocEx(process, addr, size, allocFlags, protectFlag) };
    match addr as u64 {
        0 => Err("Memory allocation failed".to_string()),
        _ => Ok(addr)
    }
}

fn write_memory(process: HANDLE, addr: *const c_void, buffer: *const c_void, size: usize) -> core::result::Result<(), String> {
    let mut size_written = 0;
    let written = unsafe { WriteProcessMemory(process, addr, buffer, size, &mut size_written).as_bool() };
    match written && size_written == size {
        true => Ok(()),
        _ => Err("Failed to write into process space".to_string()),
    }
}

fn free_memory(process: HANDLE, addr: *const c_void) {
    unsafe { VirtualFreeEx(process, addr as *mut c_void, 0, MEM_RELEASE) };
}

fn change_permission(process: HANDLE, addr: *const c_void, size: usize, protectFlag: PAGE_PROTECTION_FLAGS) -> core::result::Result<PAGE_PROTECTION_FLAGS, String> {
    let mut old_protect = PAGE_READWRITE;
    let res = unsafe { VirtualProtectEx(process, addr, size, PAGE_EXECUTE_READ, &mut old_protect).as_bool() };
    match res {
        true => Ok(old_protect),
        false => Err("Failed to change the page protection".to_string())
    }
}

fn read_memory(process: HANDLE, addr: *const c_void, buffer: *mut c_void, size: usize) -> core::result::Result<*mut c_void, String>{
    let mut size_red = 0;
    let red = unsafe { ReadProcessMemory(process, addr, buffer, size, &mut size_red).as_bool() };
    match red && size_red == size {
        true => Ok(buffer),
        _ => Err("Failed to write into process space".to_string()),
    }
}

fn create_thread(process: HANDLE, start_addr: ShellcodeFn, arg_ptr: *const c_void,) -> core::result::Result<(), String> {
    let mut tid = 0;
    let thread = unsafe { CreateRemoteThread(process, std::ptr::null(), 0, Some(start_addr), arg_ptr, 0, &mut tid) };

    match thread {
        Ok(t) => { unsafe { CloseHandle(t); }; Ok(())},
        Err(e) => return Err(e.to_string()),
    }
}

fn manual_map(process: HANDLE, dll_vec: Vec<u8>, shellcode_path: String, entrypoint_offset: Option<u64>) -> core::result::Result<(), String>{

    let dll = match PeView::from_bytes(&dll_vec) {
        Ok(o) => o,
        Err(e) => return Err(e.to_string())
    };

    let dll_opt_hdr = dll.optional_header();

    let target_base: *const c_void = unsafe { std::mem::transmute(dll_opt_hdr.ImageBase) };
    let entrypoint_offset = match entrypoint_offset {
        Some(offset) => offset,
        None => dll_opt_hdr.AddressOfEntryPoint as u64
    };
    let target_base = get_memory(process, target_base, dll_opt_hdr.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    let target_base = match target_base {
        Ok(a) => a,
        _ => get_memory(process, std::ptr::null(), dll_opt_hdr.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)?,
    };

    // Putting the DLL header into the process
    write_memory(process, target_base, dll_vec.as_ptr() as u64 as *const c_void, 0x1000)?;

    let section_headers = dll.section_headers();

    for section in section_headers.iter() {
        if section.SizeOfRawData > 0 {
            let sliced = &dll_vec[section.PointerToRawData as usize..(section.PointerToRawData + section.SizeOfRawData) as usize];
            match write_memory(process, (target_base as u64 + section.VirtualAddress as u64) as *const c_void, sliced.as_ptr() as u64 as *const c_void, section.SizeOfRawData as usize){
                Err(e) => { free_memory(process, target_base as *mut c_void); return Err(e) } ,
                _ => {},
            };
        }
    }

    // Getting the address of LoadLibraryA and get GetProcAddress
    let load_library = get_function_address("kernel32.dll\0", "LoadLibraryA\0")?;
    let get_proc_address = get_function_address("kernel32.dll\0", "GetProcAddress\0")?;
    

    // Arguments needed for the payload to do its magic
    let params = ShellcodeParams {
        load_library: load_library as u64, // 
        get_proc_address:  get_proc_address as u64,
        dll_base: target_base as u64,
        entrypoint: target_base as u64 + entrypoint_offset,
        done: 0,
    };

    let param_addr = get_memory(process, std::ptr::null(), std::mem::size_of::<ShellcodeParams>(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)?;
    // Copying needed informations to the dll address space (Keep the dll struct intact)
    write_memory(process, param_addr, vec!(params.load_library, params.get_proc_address, params.dll_base, params.entrypoint, params.done).as_ptr() as u64 as *const c_void, std::mem::size_of::<ShellcodeParams>())?;

    let shellcode = parse_coff_for_shellcode(shellcode_path)?;

    let shellcode_addr = get_memory(process, std::ptr::null(), shellcode.len() as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)?;

    write_memory(process, shellcode_addr, shellcode.as_ptr() as *const c_void, shellcode.len())?;

    change_permission(process, shellcode_addr, shellcode.len(), PAGE_EXECUTE_READ)?;

    let shellcode_func_ptr: ShellcodeFn = unsafe { std::mem::transmute(shellcode_addr) };
    create_thread(process, shellcode_func_ptr, param_addr)?;

    loop {
        let params = read_memory(process, param_addr, std::ptr::addr_of!(params) as *mut c_void, std::mem::size_of::<ShellcodeParams>())? as *const ShellcodeParams;
        if unsafe { (*params).done } != 0 {
            break 
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    println!("Done");
    Ok(())
}

// Need to use core::result::Result to avoid using the windows one
fn reflective_load(_process: windows::Win32::Foundation::HANDLE, _dll: Vec<u8>) -> core::result::Result<(), String>{
    Err("Not implemented yet".to_string())
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
    /// UNSTABLE: The path to the file to get the shellcode from, entry symbol should be main (base path is: "./src/shellcode/target/x86_64-pc-windows-msvc/debug/deps/shellcode.o"). Not tested with shellcodes that are not mine. 
    #[clap(short='S')]
    path_to_shellcode: Option<String>,
    // Build the shellcode ? 
    #[clap(short = 'B')]
    build: bool,
}

fn build_payload() -> core::result::Result<(), String>{
    let config = cargo::util::config::Config::new(cargo::core::shell::Shell::new(), fs::canonicalize(path::PathBuf::from("./src/shellcode/")).unwrap(),dirs::home_dir().unwrap().join(".cargo"));


    let workspace = cargo::core::Workspace::new(fs::canonicalize(path::PathBuf::from("./src/shellcode/Cargo.toml")).expect("Couldn't get the path as absolute").as_path(), &config).expect("Couldn't create build workspace");
    let _build = cargo::ops::compile(&workspace, &cargo::ops::CompileOptions::new(&config, cargo::core::compiler::CompileMode::Build).expect("Failed to get compile options")).expect("Failed to build");
    Ok(())
}

fn main() {
    let args = Args::parse();
    let pid = args.pid;
    let path_to_dll = args.path_to_dll;
    let build = args.build;
    let path_to_shellcode = match args.path_to_shellcode {
        Some(p) => p,
        None => "./src/shellcode/target/x86_64-pc-windows-msvc/debug/deps/shellcode.o".to_string()
    };

    if build {
        build_payload().expect("Failed to build");
    }

    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid).expect("Cannot open process with given PID") };

    let dll = match fs::read(path_to_dll) {
        Ok(file) => file,
        Err(_) => panic!("Cannot read file at dll path")
    };

    match manual_map(process, dll, path_to_shellcode, None){
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };

    unsafe { CloseHandle(process); };
}
