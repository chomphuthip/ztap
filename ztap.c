#include<stdint.h>

#define _WIN32_LEAN_AND_MEAN
#include<Windows.h>

#ifdef _ztap_cringe_overoptimization
#include <emmintrin.h>
#endif

#include "ztap.h"

typedef LPVOID(WINAPI* f_VirtualAlloc)
(LPVOID lpAddress, SIZE_T dwSize,
	DWORD  flAllocationType, DWORD  flProtect);

typedef BOOL(WINAPI* f_VirtualProtect)
(LPVOID lpAddress, SIZE_T dwSize,
	DWORD  flNewProtect, PDWORD lpflOldProtect);

typedef BOOL(WINAPI* f_VirtualFree)
(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect);

typedef HANDLE(WINAPI* f_CreateThread)
(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress, LPVOID lpParameter,
	DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef HANDLE(WINAPI* f_CreateFileMapping)
(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect, DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow, LPCSTR lpName);

typedef LPVOID(WINAPI* f_MapViewOfFile)
(HANDLE hFileMappingObject, DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh, DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap);

typedef HINSTANCE(WINAPI* f_LoadLibraryA)
(const char* lpLibFilename);

typedef FARPROC(WINAPI* f_GetProcAddress)
(HMODULE hModule, LPCSTR lpProcName);

typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)
(void* hDll, DWORD dwReason, void* pReserved);

typedef BOOL(WINAPIV* f_RtlAddFunctionTable)
(PRUNTIME_FUNCTION FunctionTable,
	DWORD EntryCount, DWORD64 BaseAddress);

typedef BOOL(WINAPI* f_ReadFile)
(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

typedef void(WINAPI* f_Sleep)
(DWORD dwMilliseconds);

inline void* _memcpy(void* dest, void* src, size_t len) {
	char* reading_head;
	char* writing_head;
	size_t to_copy;
	
	reading_head = src;
	writing_head = dest;
	to_copy = len;

#ifdef _ztap_cringe_overoptimization
	/* 
		check if reading and writing head could both be aligned
			on a 16 byte boundary at some point
	*/

	/* get each pointers distance from a 16 byte boundary */
	uintptr_t read_dist_from_16b = (uintptr_t)reading_head & 0xf;
	uintptr_t write_dist_from_16b = (uintptr_t)writing_head & 0xf;

	/* check the distance in offsets */
	uintptr_t offset_diff = read_dist_from_16b - write_dist_from_16b;

	/* if can be aligned eventually */
	if (offset_diff & 0xf == 0) {
		int until_good = offset_diff;

		while (until_good--)
			*writing_head++ = *reading_head++;

		/* aligned now */
		while (to_copy >= 16) {
			__m128i data = _mm_load_si128((__m128i*)(src));
			_mm_store_si128((__m128i*)(dest), data);
			reading_head += 16;
			writing_head += 16;
			to_copy -= 16;
		}
	}
#endif
	while (to_copy--) { *writing_head++ = *reading_head++; }
	return dest;
}

enum _oneshot_mode_t {
	DISK,
	BUFF
};

struct _oneshot_params {
	f_VirtualFree _VirtualFree;
	f_VirtualAlloc _VirtualAlloc;
	f_LoadLibraryA _LoadLibraryA;
	f_CreateThread _CreateThread;
	f_MapViewOfFile _MapViewOfFile;
	f_VirtualProtect _VirtualProtect;
	f_GetProcAddress _GetProcAddress;
	f_CreateFileMapping _CreateFileMapping;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	enum _oneshot_mode_t mode;
	union {
		char* file_loc;
		HANDLE file_handle;
	} src;
};

DWORD WINAPI _oneshot_loader(struct _oneshot_params* params) {

	/* Setting up functions */
	f_VirtualFree _VirtualFree;
	f_VirtualAlloc _VirtualAlloc;
	f_LoadLibraryA _LoadLibraryA;
	f_CreateThread _CreateThread;
	f_MapViewOfFile _MapViewOfFile;
	f_VirtualProtect _VirtualProtect;
	f_GetProcAddress _GetProcAddress;
	f_CreateFileMapping _CreateFileMapping;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	_VirtualFree = params->_VirtualFree;
	_VirtualAlloc = params->_VirtualAlloc;
	_LoadLibraryA = params->_LoadLibraryA;
	_CreateThread = params->_CreateThread;
	_MapViewOfFile = params->_MapViewOfFile;
	_VirtualProtect = params->_VirtualProtect;
	_GetProcAddress = params->_GetProcAddress;
	_CreateFileMapping = params->_CreateFileMapping;
	_RtlAddFunctionTable = params->_RtlAddFunctionTable;

	/* Getting file in memory */
	char* file_loc;
	if (params->mode == BUFF) {
		file_loc = params->src.file_loc;
	}
	else {
		HANDLE file_map;
		HANDLE file_handle;

		file_handle = params->src.file_handle;
		file_map = _CreateFileMapping(file_handle,
			NULL, PAGE_READONLY, 0, 0, NULL);
		file_loc = _MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0);
	}

	/* Writing the image to the correct locations */
	IMAGE_DOS_HEADER* file_dos_h;
	IMAGE_NT_HEADERS* file_nt_h;
	IMAGE_OPTIONAL_HEADER* file_opt_h;
	IMAGE_FILE_HEADER* file_file_h;

	file_dos_h = file_loc;
	file_nt_h = file_loc + file_dos_h->e_lfanew;
	file_opt_h = &file_nt_h->OptionalHeader;
	file_file_h = &file_nt_h->FileHeader;

	char* image_base;
	image_base = _VirtualAlloc((void*)0, file_opt_h->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	_memcpy(image_base, file_loc, 0x1000);

	IMAGE_SECTION_HEADER* section_header;
	section_header = IMAGE_FIRST_SECTION(file_nt_h);

	for (uint32_t i = 0; i < file_file_h->NumberOfSections; i++) {
		if (!section_header->SizeOfRawData)
			continue;

		_memcpy(image_base + section_header->VirtualAddress,
			file_loc + section_header->PointerToRawData,
			section_header->SizeOfRawData);
		
		section_header++;
	}


	/* Fixing relocations */
	IMAGE_DOS_HEADER* img_dos_h;
	IMAGE_NT_HEADERS* img_nt_h;
	IMAGE_OPTIONAL_HEADER* img_opt_h;
	IMAGE_FILE_HEADER* img_img_h;

	img_dos_h = image_base;
	img_nt_h = image_base + img_dos_h->e_lfanew;
	img_opt_h = &img_nt_h->OptionalHeader;
	img_img_h = &img_nt_h->FileHeader;

	IMAGE_DATA_DIRECTORY* dd;
	dd = img_opt_h->DataDirectory;

	int delta;
	IMAGE_BASE_RELOCATION* reloc_entry;
	delta = image_base - img_opt_h->ImageBase;
	reloc_entry = &dd[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	IMAGE_BASE_RELOCATION* reloc_data;
	reloc_data = image_base + reloc_entry->VirtualAddress;

	while (reloc_data->VirtualAddress) {
		if (reloc_data->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
			int count;
			count = (reloc_data->SizeOfBlock -
				sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			uint16_t* list;
			list = reloc_data + 1;

			for (int i = 0; i < count; i++) {
				if (!list[i]) continue;

				uint32_t* offset_ptr;
				offset_ptr = image_base +
					(reloc_data->VirtualAddress +
						(list[i] & 0xfff));

				*offset_ptr += delta;
			}
		}

		reloc_data = (char*)reloc_data + reloc_data->SizeOfBlock;
	}

	/* Fixing imports */
	IMAGE_DATA_DIRECTORY* import_dir_entry;
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor;

	import_dir_entry = &dd[IMAGE_DIRECTORY_ENTRY_IMPORT];
	import_descriptor = image_base + import_dir_entry->VirtualAddress;

	while (import_descriptor->Name) {
		char* lib_name;
		lib_name = image_base + import_descriptor->Name;

		HINSTANCE dll_handle;
		dll_handle = _LoadLibraryA(lib_name);

		uint64_t* thunk_ref;
		uint64_t* func_ref;

		thunk_ref = image_base + import_descriptor->OriginalFirstThunk;
		func_ref = image_base + import_descriptor->FirstThunk;
		if (!thunk_ref) thunk_ref = func_ref;

		for (; *thunk_ref; thunk_ref++, func_ref++) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
				*func_ref = _GetProcAddress(dll_handle,
					(char*)(*thunk_ref & 0xfff));
			else
				*func_ref = _GetProcAddress(dll_handle,
					((IMAGE_IMPORT_BY_NAME*)
						(image_base + (*thunk_ref)))->Name);
		}

		import_descriptor++;
	}
	
	/* Calling TLS callbacks */

	IMAGE_DATA_DIRECTORY* tls_entry;
	tls_entry = &dd[IMAGE_DIRECTORY_ENTRY_TLS];

	if (tls_entry->Size) {
		IMAGE_TLS_DIRECTORY* tls_dir;
		PIMAGE_TLS_CALLBACK* callback;

		tls_dir = image_base + tls_entry->VirtualAddress;
		callback = tls_dir->AddressOfCallBacks;
		for (; callback && *callback; callback++) {
			(*callback)(image_base, DLL_PROCESS_ATTACH, (void*)0);
		}
	}

	/* Loading exceptions */
	IMAGE_DATA_DIRECTORY* seh_entry;
	seh_entry = &dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (seh_entry->Size) {
		_RtlAddFunctionTable(
			image_base + seh_entry->VirtualAddress,
			seh_entry->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
			image_base);
	}

	f_DLL_ENTRY_POINT _entry;
	_entry = image_base + img_opt_h->AddressOfEntryPoint;

	_entry(image_base, DLL_PROCESS_ATTACH, (void*)0);

	return 0;
}

void set_oneshot_funcs(struct _oneshot_params* params) {
	params->_VirtualFree = VirtualFree;
	params->_VirtualAlloc = VirtualAlloc;
	params->_LoadLibraryA = LoadLibraryA;
	params->_CreateThread = CreateThread;
	params->_MapViewOfFile = MapViewOfFile;
	params->_VirtualProtect = VirtualProtect;
	params->_GetProcAddress = GetProcAddress;
	params->_CreateFileMapping = CreateFileMappingA;
	params->_RtlAddFunctionTable = RtlAddFunctionTable;
}

struct _ztap_disk_pkg_t {
	char code_buf[0x1000];
	struct _oneshot_params params;
};


int ztap_disk(HANDLE proc_handle, HANDLE file_handle) {
	HANDLE remote_handle;
	BOOL duplicated;
	duplicated = DuplicateHandle(
		GetCurrentProcess(),
		file_handle,
		proc_handle,
		&remote_handle,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	);
	if (!duplicated) return -1;

	struct _oneshot_params params;
	set_oneshot_funcs(&params);
	params.mode = DISK;
	params.src.file_handle = remote_handle;

	struct _ztap_disk_pkg_t* pkg;
	pkg = calloc(1, sizeof(*pkg));
	if (pkg == 0) return -2;

	memcpy(&pkg->params, &params, sizeof(params));
	memcpy(&pkg->code_buf, _oneshot_loader, 0x1000);

	struct _ztap_disk_pkg_t* remote_pkg;
	remote_pkg = VirtualAllocEx(proc_handle, (void*)0,
		sizeof(*remote_pkg), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (remote_pkg == 0) return -3;

	BOOL wrote_properly;
	wrote_properly = WriteProcessMemory(proc_handle, 
		remote_pkg, pkg, sizeof(*pkg), (void*)0);
	if (!wrote_properly) return -4;

	HANDLE thread_handle;
	thread_handle = CreateRemoteThread(proc_handle,
		(void*)0, 0, remote_pkg->code_buf,
		&remote_pkg->params, 0, 0);
	if (thread_handle == NULL) return -5;

	return 0;
}

struct _ztap_buff_pkg_t {
	char code_buf[0x1000];
	struct _oneshot_params params;
	
	char padding[0xf];
};

int ztap_buff(HANDLE proc_handle, char* buff, size_t buff_len) {
	struct _ztap_buff_pkg_t* remote_pkg;
	remote_pkg = VirtualAllocEx(proc_handle, (void*)0,
		sizeof(*remote_pkg) + buff_len, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (remote_pkg == 0) return -1;

	struct _oneshot_params params;
	set_oneshot_funcs(&params);
	params.mode = BUFF;
	params.src.file_loc = (uintptr_t)remote_pkg + sizeof(*remote_pkg);

	struct _ztap_buff_pkg_t* pkg;
	pkg = calloc(1, sizeof(*pkg) + buff_len);
	if (pkg == 0) return -2;

	memcpy(&pkg->params, &params, sizeof(params));
	memcpy(&pkg->code_buf, _oneshot_loader, 0x1000);
	memcpy((uintptr_t)pkg + sizeof(*pkg), buff, buff_len);

	BOOL wrote_properly;
	wrote_properly = WriteProcessMemory(proc_handle,
		remote_pkg, pkg, sizeof(*pkg) + buff_len, (void*)0);
	if (!wrote_properly) return -3;

	HANDLE thread_handle;
	thread_handle = CreateRemoteThread(proc_handle,
		(void*)0, 0, remote_pkg->code_buf,
		&remote_pkg->params, 0, 0);
	if (thread_handle == NULL) return -4;

	return 0;
}

struct _pipe_params {
	f_Sleep _Sleep;
	f_ReadFile _ReadFile;
	f_VirtualFree _VirtualFree;
	f_VirtualAlloc _VirtualAlloc;
	f_LoadLibraryA _LoadLibraryA;
	f_CreateThread _CreateThread;
	f_VirtualProtect _VirtualProtect;
	f_GetProcAddress _GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	HANDLE read_handle;
	size_t file_len;
};


__declspec(safebuffers) DWORD WINAPI _pipe_loader(struct _pipe_params* params) {
	
	/* Setting up functions */
	f_Sleep _Sleep;
	f_ReadFile _ReadFile;
	f_VirtualFree _VirtualFree;
	f_VirtualAlloc _VirtualAlloc;
	f_LoadLibraryA _LoadLibraryA;
	f_CreateThread _CreateThread;
	f_VirtualProtect _VirtualProtect;
	f_GetProcAddress _GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	_Sleep = params->_Sleep;
	_ReadFile = params->_ReadFile;
	_VirtualFree = params->_VirtualFree;
	_VirtualAlloc = params->_VirtualAlloc;
	_LoadLibraryA = params->_LoadLibraryA;
	_CreateThread = params->_CreateThread;
	_VirtualProtect = params->_VirtualProtect;
	_GetProcAddress = params->_GetProcAddress;
	_RtlAddFunctionTable = params->_RtlAddFunctionTable;

	/* Read file from pipe */
	char* file_loc;
	file_loc = _VirtualAlloc((void*)0, params->file_len,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	_Sleep(1000);

	char* writing_head;
	size_t total_read;
	size_t read;

	total_read = 0;
	writing_head = file_loc;
	while (total_read < params->file_len) {
		_ReadFile(params->read_handle, writing_head, 
			params->file_len, &read, (void*)0);
		
		total_read += read;
		writing_head += read;
	}

	/* Writing the image to the correct locations */
	IMAGE_DOS_HEADER* file_dos_h;
	IMAGE_NT_HEADERS* file_nt_h;
	IMAGE_OPTIONAL_HEADER* file_opt_h;
	IMAGE_FILE_HEADER* file_file_h;

	file_dos_h = file_loc;
	file_nt_h = file_loc + file_dos_h->e_lfanew;
	file_opt_h = &file_nt_h->OptionalHeader;
	file_file_h = &file_nt_h->FileHeader;

	char* image_base;
	image_base = _VirtualAlloc((void*)0, file_opt_h->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	_memcpy(image_base, file_loc, 0x1000);

	IMAGE_SECTION_HEADER* section_header;
	section_header = IMAGE_FIRST_SECTION(file_nt_h);

	for (uint32_t i = 0; i < file_file_h->NumberOfSections; i++) {
		if (!section_header->SizeOfRawData)
			continue;

		_memcpy(image_base + section_header->VirtualAddress,
			file_loc + section_header->PointerToRawData,
			section_header->SizeOfRawData);

		section_header++;
	}


	/* Fixing relocations */
	IMAGE_DOS_HEADER* img_dos_h;
	IMAGE_NT_HEADERS* img_nt_h;
	IMAGE_OPTIONAL_HEADER* img_opt_h;
	IMAGE_FILE_HEADER* img_img_h;

	img_dos_h = image_base;
	img_nt_h = image_base + img_dos_h->e_lfanew;
	img_opt_h = &img_nt_h->OptionalHeader;
	img_img_h = &img_nt_h->FileHeader;

	IMAGE_DATA_DIRECTORY* dd;
	dd = img_opt_h->DataDirectory;

	int delta;
	IMAGE_BASE_RELOCATION* reloc_entry;
	delta = image_base - img_opt_h->ImageBase;
	reloc_entry = &dd[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	IMAGE_BASE_RELOCATION* reloc_data;
	reloc_data = image_base + reloc_entry->VirtualAddress;

	while (reloc_data->VirtualAddress) {
		if (reloc_data->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
			int count;
			count = (reloc_data->SizeOfBlock -
				sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			uint16_t* list;
			list = reloc_data + 1;

			for (int i = 0; i < count; i++) {
				if (!list[i]) continue;

				uint32_t* offset_ptr;
				offset_ptr = image_base +
					(reloc_data->VirtualAddress +
						(list[i] & 0xfff));

				*offset_ptr += delta;
			}
		}

		reloc_data = (char*)reloc_data + reloc_data->SizeOfBlock;
	}

	/* Fixing imports */
	IMAGE_DATA_DIRECTORY* import_dir_entry;
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor;

	import_dir_entry = &dd[IMAGE_DIRECTORY_ENTRY_IMPORT];
	import_descriptor = image_base + import_dir_entry->VirtualAddress;

	while (import_descriptor->Name) {
		char* lib_name;
		lib_name = image_base + import_descriptor->Name;

		HINSTANCE dll_handle;
		dll_handle = _LoadLibraryA(lib_name);

		uint64_t* thunk_ref;
		uint64_t* func_ref;

		thunk_ref = image_base + import_descriptor->OriginalFirstThunk;
		func_ref = image_base + import_descriptor->FirstThunk;
		if (!thunk_ref) thunk_ref = func_ref;

		for (; *thunk_ref; thunk_ref++, func_ref++) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
				*func_ref = _GetProcAddress(dll_handle,
					(char*)(*thunk_ref & 0xfff));
			else
				*func_ref = _GetProcAddress(dll_handle,
					((IMAGE_IMPORT_BY_NAME*)
						(image_base + (*thunk_ref)))->Name);
		}

		import_descriptor++;
	}

	/* Calling TLS callbacks */

	IMAGE_DATA_DIRECTORY* tls_entry;
	tls_entry = &dd[IMAGE_DIRECTORY_ENTRY_TLS];

	if (tls_entry->Size) {
		IMAGE_TLS_DIRECTORY* tls_dir;
		PIMAGE_TLS_CALLBACK* callback;

		tls_dir = image_base + tls_entry->VirtualAddress;
		callback = tls_dir->AddressOfCallBacks;
		for (; callback && *callback; callback++) {
			(*callback)(image_base, DLL_PROCESS_ATTACH, (void*)0);
		}
	}

	/* Loading exceptions */
	IMAGE_DATA_DIRECTORY* seh_entry;
	seh_entry = &dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (seh_entry->Size) {
		_RtlAddFunctionTable(
			image_base + seh_entry->VirtualAddress,
			seh_entry->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
			image_base);
	}

	f_DLL_ENTRY_POINT _entry;
	_entry = image_base + img_opt_h->AddressOfEntryPoint;

	_entry(image_base, DLL_PROCESS_ATTACH, (void*)0);

	return 0;
}

void set_pipe_funcs(struct _pipe_params* params) {
	params->_Sleep = Sleep;
	params->_ReadFile = ReadFile;
	params->_VirtualFree = VirtualFree;
	params->_VirtualAlloc = VirtualAlloc;
	params->_LoadLibraryA = LoadLibraryA;
	params->_CreateThread = CreateThread;
	params->_VirtualProtect = VirtualProtect;
	params->_GetProcAddress = GetProcAddress;
	params->_RtlAddFunctionTable = RtlAddFunctionTable;
}

struct _ztap_pipe_pkg_t {
	char code_buf[0x1000];
	struct _pipe_params params;
};

int ztap_pipe(HANDLE proc_handle, char* buff, size_t buff_len) {
	HANDLE write_handle;
	HANDLE read_handle;
	BOOL piped;
	
	piped = CreatePipe(&read_handle, &write_handle, (void*)0, 0);
	if (piped == FALSE) return -1;

	HANDLE remote_handle;
	BOOL duplicated;
	duplicated = DuplicateHandle(
		GetCurrentProcess(),
		read_handle,
		proc_handle,
		&remote_handle,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	);
	if (!duplicated) return -2;

	struct _pipe_params params;
	set_pipe_funcs(&params);
	params.read_handle = remote_handle;
	params.file_len = buff_len;

	struct _ztap_pipe_pkg_t* pkg;
	pkg = calloc(1, sizeof(*pkg));
	if (pkg == 0) return -3;

	memcpy(&pkg->params, &params, sizeof(params));
	memcpy(&pkg->code_buf, _pipe_loader, 0x1000);

	struct _ztap_disk_pkg_t* remote_pkg;
	remote_pkg = VirtualAllocEx(proc_handle, (void*)0,
		sizeof(*remote_pkg), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (remote_pkg == 0) return -4;

	BOOL wrote_properly;
	wrote_properly = WriteProcessMemory(proc_handle,
		remote_pkg, pkg, sizeof(*pkg), (void*)0);
	if (!wrote_properly) return -5;

	HANDLE thread_handle;
	thread_handle = CreateRemoteThread(proc_handle,
		(void*)0, 0, remote_pkg->code_buf,
		&remote_pkg->params, 0, 0);
	if (thread_handle == NULL) return -6;

	char* writing_head;
	size_t total_sent;
	size_t sent;

	total_sent = 0;
	writing_head = buff;
	while (total_sent < buff_len) {
		WriteFile(write_handle,
			writing_head,
			buff_len,
			&sent,
			NULL
		);
		total_sent += sent;
		writing_head += sent;
	}

	CloseHandle(read_handle);
	CloseHandle(write_handle);
	
	return 0;
}
