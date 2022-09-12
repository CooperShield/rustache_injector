# Rustache Loader

This is aimed to be usable both as a standalone binary and as a library (is that even doable ? Will find out)
The aim of the project is to implement different method of DLL injection into a remote process

This project use the windows crate to interact with Windows and the PeLite to parse the PE, will try to make it better to avoid PeLite (used to test faster) and try to include direct syscalling.
May add the handling of user selected shellcode, by taking a COFF and searching for a symbol given by the user.

## Usage

rustache_loader -I <PID> -P <path_to_dll> -S <path_to_shellcode (not required if shellcode is in the shellcode build directory)> -B (build shellcode ? from the source dir)

## Roadmap

### Manual Mapping
My code load and set the DLL, then call the entry point

#### Todo
Handle more shellcode, at least with a different symbol name


### Reflective Loading
My code put the DLL in the memory map of the process, create a thread and the DLL set itself up

### LoadLibrary
I've already done a LoadLibrary one in rust before so it'll be added later

### x86 support
TODO

### Handle more complex Dll
Maybe
Then i'll try to get a better PE Loader

### WhichGateWillItBe Evasion Universe

Hopefully making it so that the user can chose which one to use


# References

## GuidedHacking (https://guidedhacking.com/)
For the Manual map tutorial + the multiples threads and answer to better it
