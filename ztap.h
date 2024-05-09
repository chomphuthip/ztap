#include<Windef.h>

/*
	Creates a loader thread in the target process.
	Loader thread loads the file and maps it.

	Return values:
		0: Success
		-1: Couldn't duplicate handle
		-2: Couldn't allocate memory locally
		-3: Couldn't allocate memory in target process
		-4: Couldn't write to memory in target process
		-5: Couldn't start thread in target process
*/

int ztap_disk(HANDLE proc_handle, HANDLE file_handle);

/*
	Writes the raw PE file to the target process.
	Creates a loader thread in the target process.
	Loader thread maps the PE file from memory.

	Return values:
		0: Success
		-1: Couldn't allocate memory locally
		-2: Couldn't allocate memory in target process
		-3: Couldn't write to memory in target process
		-4: Couldn't start thread in target process
*/
int ztap_buff(HANDLE proc_handle, char* buff, size_t buff_len);

/*
	Opens two unnamed pipes.
	Duplicates handles for loader thread.
	Creates a loader thread in the target process.
	Writes file to unnamed pipe until EOF.
	Loader reads file from unnamed pipe into buffer.
	Loader maps PE from memory.

	Return values:
		0: Success
		-1: Couldn't create pipe
		-2: Couldn't duplicate handle
		-3: Couldn't allocate memory locally
		-4: Couldn't allocate memory in target process
		-5: Couldn't write to memory in target process
		-6: Couldn't start thread in target process
*/
int ztap_pipe(HANDLE proc_handle, char* buff, size_t buff_len);


/*
	Commander mode uses pipes to dispatch Winapi calls.
	Winapi calls will be called from inside the process.
	You can immediately close your process handle.
*/

struct ztap_handle_t {
	HANDLE pipe_read;
	HANDLE pipe_write;
	DWORD last_error;
};

int ztap_cmdr_init(HANDLE proc_handle,
	struct ztap_handle_t* handle);

BOOL ztap_cmdr_wpm(
	struct ztap_handle_t* handle,
	void* base_address,
	void* buffer,
	size_t size,
	size_t* out_size
);

BOOL ztap_cmdr_rpm(
	struct ztap_handle_t* handle,
	void* base_address,
	void* buffer,
	size_t size,
	size_t* out_size
);

LPVOID ztap_cmdr_va(
	struct ztap_handle_t* handle,
	void* address,
	size_t size,
	uint32_t allocation_type,
	uint32_t  protect
);

BOOL ztap_cmdr_vp(
	struct ztap_handle_t* handle,
	void* address,
	size_t size,
	uint32_t new_protect,
	uint32_t*  old_protect
);

BOOL ztap_cmdr_vf(
	struct ztap_handle_t* handle,
	void* address,
	size_t size,
	uint32_t free_type
);

HMODULE ztap_cmdr_lla(
	struct ztap_handle_t* handle,
	char* lib_name
);

FARPROC ztap_cmdr_gpa(
	struct ztap_handle_t* handle,
	HMODULE module_handle,
	char* name
);

void ztap_cmdr_ct(
	struct ztap_handle_t* handle,
	SECURITY_ATTRIBUTES* thread_attributes,
	size_t stack_size,
	void*  start_address,
	void* parameter,
	DWORD creation_flags,
	DWORD* thread_id
);

int ztap_cmdr_ncc(
	struct ztap_handle_t* handle,
	char* start,
	uint64_t size,
	uint64_t range,
	char** code_cave_ptr
);

int ztap_cmdr_fcc(
	struct ztap_handle_t* handle,
	char* start,
	uint64_t size,
	char* end,
	char** code_cave_ptr
);

int ztap_cmdr_end(struct ztap_handle_t* ztap_handle);