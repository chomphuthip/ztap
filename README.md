# ztap
Process injection library that minimizes process-related API calls

ztap uses only
* one `VirtualAllocEx` call
* one `WriteProcessMemory` call
* and one `CreateRemoteThread` call

Features Roadmap
* ✔ Injection using file handle
* ✔ Reflective Injection
* ✔ Pipe-based Injection
* Commander Mode
