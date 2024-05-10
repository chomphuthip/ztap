# ztap
Process injection library that minimizes process-related API calls

ztap uses only
* one `VirtualAllocEx` call
* one `WriteProcessMemory` call
* and one `CreateRemoteThread` call

### Novel Techniques
Commander mode injects a thread that listens on an anonymous pipe for requests from the injector. The thread will listen on the pipe and call internal versions of highly scrutinized functions like `VirutalAllocEx`, `WriteProcessMemory`, and `LoadLibraryEx`. 

Attackers can now call functions that are critical for process injection without maintaining a process handle. After initializing commander mode, the process handle is no longer necessary and can be closed immediately. 

### Features Roadmap
✔ Injection using file handle\
✔ Reflective Injection\
✔ Pipe-based Injection\
✔ Commander Mode
