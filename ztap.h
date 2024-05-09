#include<Windef.h>

/*
	Creates a loader thread in the target process.
	Loader thread loads the file and maps it.

	Return values:
		0: Success
		1: Couldn't duplicate handle
		2: Couldn't allocate memory locally
		3: Couldn't allocate memory in target process
		4: Couldn't write to memory in target process
		5: Couldn't start thread in target process
*/

int ztap_disk(HANDLE proc_handle, HANDLE file_handle);

/*
	Writes the raw PE file to the target process.
	Creates a loader thread in the target process.
	Loader thread maps the PE file from memory.

	Return values:
		0: Success
		1: Couldn't allocate memory locally
		2: Couldn't allocate memory in target process
		3: Couldn't write to memory in target process
		4: Couldn't start thread in target process
*/
int ztap_buff(HANDLE proc_handle, char* buff, size_t buff_len);

int ztap_pipe(HANDLE proc_handle, char* buff, size_t buff_len);


//struct ztap_handle_t {
//	HANDLE pipe_read;
//	HANDLE pipe_write;
//};
//
//int ztap_cmdr_init(HANDLE proc_handle,
//	struct ztap_handle_t ztap_handle);
//
//int ztap_cmdr_wpm(
//	struct ztap_handle_t ztap_handle,
//	void* base_address,
//	void* buffer,
//	size_t size,
//	size_t* out_size
//);
