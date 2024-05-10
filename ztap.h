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
*/

struct ztap_handle_t {
	HANDLE pipe_read;
	HANDLE pipe_write;
	DWORD last_error;
};

/*
	Executes cmdr_thread in target process and opens a ztap handle.
	You can immediately close your process handle after calling.

		Return values:
		0: Success
		-1: Couldn't create cmdr_write pipe
		-2: Couldn't duplicate cmdr_write read handle
		-3: Couldn't create cmdr_read pipe
		-4: Couldn't duplicate cmdr_read write handle
		-5: Couldn't allocate memory locally
		-6: Couldn't allocate memory in target process
		-7: Couldn't write to memory in target process
		-8: Couldn't start thread in target process
*/
int ztap_cmdr_init(HANDLE proc_handle,
	struct ztap_handle_t* handle);

/*
	Equivalent to WriteProcessMemory.

		Return values:
		TRUE: Success
		FALSE: Error
*/
BOOL ztap_cmdr_wpm(
	struct ztap_handle_t* handle,
	void* base_address,
	void* buffer,
	size_t size,
	size_t* out_size
);

/*
	Equivalent to ReadProcessMemory.

		Return values:
		TRUE: Success
		FALSE: Error
*/
BOOL ztap_cmdr_rpm(
	struct ztap_handle_t* handle,
	void* base_address,
	void* buffer,
	size_t size,
	size_t* out_size
);

/*
	Equivalent to calling VirtualAlloc inside of the target process.

		Return values:
		0: Error
		Non 0: Pointer to newly allocated memory
*/
LPVOID ztap_cmdr_va(
	struct ztap_handle_t* handle,
	void* address,
	size_t size,
	uint32_t allocation_type,
	uint32_t  protect
);

/*
	Equivalent to calling VirtualProtect inside of the target process.

		Return values:
		TRUE: Success
		FALSE: Error
*/
BOOL ztap_cmdr_vp(
	struct ztap_handle_t* handle,
	void* address,
	size_t size,
	uint32_t new_protect,
	uint32_t*  old_protect
);

/*
	Equivalent to calling VirtualFree inside of the target process.

		Return values:
		TRUE: Success
		FALSE: Error
*/
BOOL ztap_cmdr_vf(
	struct ztap_handle_t* handle,
	void* address,
	size_t size,
	uint32_t free_type
);

/*
	Equivalent to calling LoadLibaryA inside of the target process.
	lib_name must be less than 254 characters.

		Return values:
		TRUE: Success
		FALSE: Error
*/
HMODULE ztap_cmdr_lla(
	struct ztap_handle_t* handle,
	char* lib_name
);

/*
	Equivalent to calling GetProcAddress inside of the target process.
	name must be less than 254 characters.

		Return values:
		TRUE: Success
		FALSE: Error
*/
FARPROC ztap_cmdr_gpa(
	struct ztap_handle_t* handle,
	HMODULE module_handle,
	char* name
);

/*
	Equivalent to calling CreateThread inside of the target process.
*/
void ztap_cmdr_ct(
	struct ztap_handle_t* handle,
	SECURITY_ATTRIBUTES* thread_attributes,
	size_t stack_size,
	void*  start_address,
	void* parameter,
	DWORD creation_flags,
	DWORD* thread_id
);

/*
	Finds the next code cave.
	Uses a start and range to search.

		Returns:
			-1: Error
			Non -1: pointer to code cave
*/
int ztap_cmdr_ncc(
	struct ztap_handle_t* handle,
	char* start,
	uint64_t size,
	uint64_t range,
	char** code_cave_ptr
);

/*
	Finds the first code cave.
	Uses a start and end to search.

		Returns:
			-1: Error
			Non -1: pointer to code cave
*/
int ztap_cmdr_fcc(
	struct ztap_handle_t* handle,
	char* start,
	uint64_t size,
	char* end,
	char** code_cave_ptr
);

/*
	Maps a PE from a buffer in the target process's memory.

		Returns:
			TRUE: Success
*/
BOOL ztap_cmdr_mi(
	struct ztap_handle_t* handle,
	char* file_loc,
	char** image_base
);

/*
	Fixes relocation table of an image in the target process.
	Pass it the base of the image mapped by ztap_cmdr_mi

		Returns:
			TRUE: Success
*/
BOOL ztap_cmdr_fr(
	struct ztap_handle_t* handle,
	char* image_base
);

/*
	Fixes bound imports of an image in the target process.
	Pass it the base of the image mapped by ztap_cmdr_mi

		Returns:
			TRUE: Success
*/
BOOL ztap_cmdr_fi(
	struct ztap_handle_t* handle,
	char* image_base
);

/*
	Calls TLS callbacks.

		Returns:
			TRUE: Success
*/
BOOL ztap_cmdr_tls(
	struct ztap_handle_t* handle,
	char* image_base
);

/*
	Adds SEH function table.

		Returns:
			TRUE: Success
*/
BOOL ztap_cmdr_seh(
	struct ztap_handle_t* handle,
	char* image_base
);

/*
	Calls the entrypoint of an image.

		Returns:
			TRUE: Success
*/
BOOL ztap_cmdr_call(
	struct ztap_handle_t* handle,
	char* image_base
);

/*
	Closes the ztap handle
*/
void ztap_cmdr_end(struct ztap_handle_t* ztap_handle);