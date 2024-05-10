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

typedef BOOL(WINAPI* f_WriteFile)
(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

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

__forceinline void map_image(char* file_loc, char** image_base_ptr, f_VirtualAlloc _VirtualAlloc) {
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

	*image_base_ptr = image_base;
}

__forceinline void fix_relocations(char* image_base) {
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
}

__forceinline void fix_imports(char* image_base, f_LoadLibraryA _LoadLibraryA, f_GetProcAddress _GetProcAddress) {
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
}

__forceinline void call_tls_callbacks(char* image_base) {
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

	IMAGE_DATA_DIRECTORY* tls_entry;
	tls_entry = &dd[IMAGE_DIRECTORY_ENTRY_TLS];

	int delta;
	IMAGE_BASE_RELOCATION* reloc_entry;
	delta = image_base - img_opt_h->ImageBase;
	reloc_entry = &dd[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (tls_entry->Size) {
		IMAGE_TLS_DIRECTORY* tls_dir;
		PIMAGE_TLS_CALLBACK* callback;
		PIMAGE_TLS_CALLBACK callback_rebased;

		tls_dir = image_base + tls_entry->VirtualAddress;
		callback = tls_dir->AddressOfCallBacks;
		for (; callback && *callback; callback++) {
			callback_rebased = (char*)*callback + delta;
			(callback_rebased)(image_base, DLL_PROCESS_ATTACH, (void*)0);
		}
	}
}

__forceinline void load_seh(char* image_base, f_RtlAddFunctionTable _RtlAddFunctionTable) {
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

	IMAGE_DATA_DIRECTORY* seh_entry;
	seh_entry = &dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (seh_entry->Size) {
		_RtlAddFunctionTable(
			image_base + seh_entry->VirtualAddress,
			seh_entry->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
			image_base);
	}
}

__forceinline void call_entry(char* image_base) {
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

	f_DLL_ENTRY_POINT _entry;
	_entry = image_base + img_opt_h->AddressOfEntryPoint;

	_entry(image_base, DLL_PROCESS_ATTACH, (void*)0);
}


struct headers_cache {
	IMAGE_DOS_HEADER* dos_h;
	IMAGE_NT_HEADERS* nt_h;
	IMAGE_OPTIONAL_HEADER* opt_h;
	IMAGE_FILE_HEADER* file_h;
	IMAGE_DATA_DIRECTORY* dd;
};

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

	char* image_base;
	map_image(file_loc, &image_base, _VirtualAlloc);

	fix_relocations(image_base);
	fix_imports(image_base, _LoadLibraryA, _GetProcAddress);
	call_tls_callbacks(image_base);
	load_seh(image_base, _RtlAddFunctionTable);
	call_entry(image_base);

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

	_Sleep(10);

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

	char* image_base;
	map_image(file_loc, &image_base, _VirtualAlloc);

	fix_relocations(image_base);
	fix_imports(image_base, _LoadLibraryA, _GetProcAddress);
	call_tls_callbacks(image_base);
	load_seh(image_base, _RtlAddFunctionTable);
	call_entry(image_base);
	
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

/* --- WARNING --- COMMANDER MODE --- POINT OF NO RETURN --- */

struct _cmdr_params {
	f_Sleep _Sleep;
	f_ReadFile _ReadFile;
	f_WriteFile _WriteFile;
	f_VirtualFree _VirtualFree;
	f_VirtualAlloc _VirtualAlloc;
	f_LoadLibraryA _LoadLibraryA;
	f_CreateThread _CreateThread;
	f_VirtualProtect _VirtualProtect;
	f_GetProcAddress _GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	HANDLE read_handle;
	HANDLE write_handle;
};
struct _cmdr_va_params_t {
	LPVOID lpAddress;
	SIZE_T dwSize;
	DWORD flAllocationType;
	DWORD flProtect;
};

struct _cmdr_vp_params_t {
	LPVOID lpAddress;
	SIZE_T dwSize;
	DWORD flNewProtect;
	PDWORD lpflOldProtect;
};

struct _cmdr_vf_params_t {
	LPVOID lpAddress;
	SIZE_T dwSize;
	DWORD dwFreeType;
};

struct _cmdr_ct_params_t {
	LPSECURITY_ATTRIBUTES lpThreadAttributes;
	SIZE_T dwStackSize;
	LPTHREAD_START_ROUTINE lpStartAddress;
	LPVOID lpParameter;
	DWORD dwCreationFlags;
	LPDWORD lpThreadId;
};

struct _cmdr_wpm_params_t {
	size_t buff_len;
	char* dest;
};

struct _cmdr_rpm_params_t {
	size_t buff_len;
	char* src;
};

struct _cmdr_lla_params_t {
	char lpLibFilename[255];
};

struct _cmdr_gpa_params_t {
	HMODULE hModule;
	char lpProcName[255];
};

struct _cmdr_ncc_params_t {
	char* start;
	uint64_t size;
	uint64_t range;
};

struct _cmdr_fcc_params_t {
	char* start;
	uint64_t size;
	char* end;
};

struct _cmdr_end_params_t {
	uint32_t sanity;
};


enum _cmdr_msg_enum_t {
	cmdr_wpm,
	cmdr_rpm,
	cmdr_va,
	cmdr_vp,
	cmdr_vf,
	cmdr_lla,
	cmdr_gpa,
	cmdr_ct,
	cmdr_ncc,
	cmdr_fcc,
	cmdr_end
};

struct _cmdr_msg_t {
	enum _cmdr_msg_enum_t msg_enum;
	union _params {
		struct _cmdr_va_params_t _cmdr_va_params;
		struct _cmdr_vp_params_t _cmdr_vp_params;
		struct _cmdr_vf_params_t _cmdr_vf_params;
		struct _cmdr_ct_params_t _cmdr_ct_params;
		struct _cmdr_wpm_params_t _cmdr_wpm_params;
		struct _cmdr_rpm_params_t _cmdr_rpm_params;
		struct _cmdr_lla_params_t _cmdr_lla_params;
		struct _cmdr_gpa_params_t _cmdr_gpa_params;
		struct _cmdr_ncc_params_t _cmdr_ncc_params;
		struct _cmdr_fcc_params_t _cmdr_fcc_params;
		struct _cmdr_end_params_t _cmdr_end_params;

	} params;
};

enum _cmdr_res_type_t {
	error_res_t,
	HANDLE_res_t,
	BOOL_res_t,
	DWORD_res_t,
	FARPROC_res_t,
	ptr_res_t
};

struct _cmdr_res_t {
	enum _cmdr_res_type_t res_type;
	union {
		DWORD error;
		HANDLE handle;
		BOOL bool;
		FARPROC farproc;
		char* ptr;
		DWORD dword;
	} val ;
};

__declspec(safebuffers) 
DWORD WINAPI _cmdr_thread(struct _cmdr_params* params) {

	/* Setting up functions */
	f_Sleep _Sleep;
	f_ReadFile _ReadFile;
	f_WriteFile _WriteFile;
	f_VirtualFree _VirtualFree;
	f_VirtualAlloc _VirtualAlloc;
	f_LoadLibraryA _LoadLibraryA;
	f_CreateThread _CreateThread;
	f_VirtualProtect _VirtualProtect;
	f_GetProcAddress _GetProcAddress;

	_Sleep = params->_Sleep;
	_ReadFile = params->_ReadFile;
	_WriteFile = params->_WriteFile;
	_VirtualFree = params->_VirtualFree;
	_VirtualAlloc = params->_VirtualAlloc;
	_LoadLibraryA = params->_LoadLibraryA;
	_CreateThread = params->_CreateThread;
	_VirtualProtect = params->_VirtualProtect;
	_GetProcAddress = params->_GetProcAddress;

	_Sleep(10);

	struct _cmdr_msg_t msg;
	struct _cmdr_res_t res;
	size_t bytes_read;
	size_t bytes_sent;

	while (1) {
		_ReadFile(params->read_handle, &msg, sizeof(msg),
			&bytes_read, (void*)0);
		switch (msg.msg_enum) {
		case cmdr_wpm: {
			size_t recv;
			size_t total_recv;
			char* writing_head;
			struct _cmdr_wpm_params_t* wpm_params;

			recv = 0;
			total_recv = 0;
			writing_head = wpm_params->dest;
			wpm_params = &(msg.params._cmdr_wpm_params);

			while (total_recv < wpm_params->buff_len) {
				_ReadFile(
					params->read_handle,
					writing_head,
					wpm_params->buff_len,
					&recv,
					(void*)0
				);

				total_recv += recv;
				writing_head += recv;
			}

			res.res_type = BOOL_res_t;
			res.val.bool = TRUE;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_rpm: {
			size_t sent;
			size_t total_sent;
			char* reading_head;
			struct _cmdr_rpm_params_t* rpm_params;

			sent = 0;
			total_sent = 0;
			reading_head = rpm_params->src;
			rpm_params = &(msg.params._cmdr_rpm_params);

			while (total_sent < rpm_params->buff_len) {
				_WriteFile(
					params->read_handle,
					reading_head,
					rpm_params->buff_len,
					&sent,
					(void*)0
				);

				total_sent += sent;
				reading_head += sent;
			}

			res.res_type = BOOL_res_t;
			res.val.bool = TRUE;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_vf: {
			BOOL good_free;
			struct _cmdr_vf_params_t* vf_params;

			vf_params = &(msg.params._cmdr_vf_params);
			good_free = _VirtualFree(
				vf_params->lpAddress,
				vf_params->dwSize,
				vf_params->dwFreeType
			);

			res.res_type = BOOL_res_t;
			res.val.bool = good_free;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_va: {
			char* buf;
			struct _cmdr_va_params_t* va_params;

			va_params = &(msg.params._cmdr_va_params);
			buf = _VirtualAlloc(
				va_params->lpAddress,
				va_params->dwSize,
				va_params->flAllocationType,
				va_params->flProtect
			);

			res.res_type = ptr_res_t;
			res.val.ptr = buf;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_vp: {
			DWORD old_protect;
			BOOL good_protect;
			struct _cmdr_vp_params_t* vp_params;

			vp_params = &(msg.params._cmdr_vp_params);
			good_protect = _VirtualProtect(
				vp_params->lpAddress,
				vp_params->dwSize,
				vp_params->flNewProtect,
				&old_protect
			);

			if (good_protect) {
				res.res_type = DWORD_res_t;
				res.val.dword = old_protect;
			}
			else {
				res.res_type = error_res_t;
				res.val.ptr = good_protect;
			}

			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_lla: {
			HANDLE module_handle;
			struct _cmdr_lla_params_t* lla_params;

			lla_params = &(msg.params._cmdr_lla_params);
			module_handle = _LoadLibraryA(
				lla_params->lpLibFilename
			);

			res.res_type = HANDLE_res_t;
			res.val.ptr = module_handle;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_ct: {
			DWORD thread_id;
			HANDLE thread_handle;
			struct _cmdr_ct_params_t* ct_params;

			ct_params = &(msg.params._cmdr_ct_params);
			thread_handle = _CreateThread(
				ct_params->lpThreadAttributes,
				ct_params->dwStackSize,
				ct_params->lpStartAddress,
				ct_params->lpParameter,
				ct_params->dwCreationFlags,
				&thread_id
			);

			res.res_type = DWORD_res_t;
			res.val.ptr = thread_id;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_gpa: {
			FARPROC proc_addr;
			struct _cmdr_gpa_params_t* vp_params;

			vp_params = &(msg.params._cmdr_gpa_params);
			proc_addr = _GetProcAddress(
				vp_params->hModule,
				vp_params->lpProcName
			);

			res.res_type = FARPROC_res_t;
			res.val.ptr = proc_addr;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_ncc: {
			char* end;
			char* code_cave;
			size_t dist_cleared;
			struct _cmdr_ncc_params_t* ncc_params;

			ncc_params = &(msg.params._cmdr_ncc_params);
			code_cave = ncc_params->start;
			end = code_cave + ncc_params->range;

			dist_cleared = 0;
			while (code_cave < end) {
				if (*code_cave == 0xCC || *code_cave == 0x00)
					dist_cleared++;
				else
					dist_cleared = 0;

				if (dist_cleared >= ncc_params->size) break;

				code_cave++;
			}
			if (code_cave == end) {
				res.res_type = error_res_t;
				res.val.dword = -1;
			}
			else {
				res.res_type = ptr_res_t;
				res.val.ptr = code_cave;
			}

			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_fcc: {
			char* end;
			char* code_cave;
			size_t dist_cleared;
			struct _cmdr_fcc_params_t* fcc_params;

			fcc_params = &(msg.params._cmdr_fcc_params);
			code_cave = fcc_params->start;
			end = fcc_params->end;

			dist_cleared = 0;
			while (code_cave < end) {
				if (*code_cave == 0xCC || *code_cave == 0x00)
					dist_cleared++;
				else
					dist_cleared = 0;

				if (dist_cleared >= fcc_params->size) break;

				code_cave++;
			}

			if (code_cave == end) {
				res.res_type = error_res_t;
				res.val.dword = -1;
			}
			else {
				res.res_type = ptr_res_t;
				res.val.ptr = code_cave;
			}
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			break;
		}
		case cmdr_end: {
			res.res_type = DWORD_res_t;
			res.val.dword = 0;
			_WriteFile(params->write_handle, &res,
				sizeof(res), &bytes_sent, (void*)0);
			return 0;
		}
		}

		return 0;
	}
}

void set_cmdr_funcs(struct _cmdr_params* params) {
	params->_Sleep = Sleep;
	params->_ReadFile = ReadFile;
	params->_VirtualFree = VirtualFree;
	params->_VirtualAlloc = VirtualAlloc;
	params->_LoadLibraryA = LoadLibraryA;
	params->_CreateThread = CreateThread;
	params->_VirtualProtect = VirtualProtect;
	params->_GetProcAddress = GetProcAddress;
}

struct _ztap_cmdr_pkg_t {
	char code_buf[0x1000];
	struct _cmdr_params params;
};

int ztap_cmdr_init(HANDLE proc_handle, struct ztap_handle_t** handle) {
	HANDLE cmdr_write_handle;
	HANDLE msg_read_handle;
	BOOL piped;

	piped = CreatePipe(&msg_read_handle, &cmdr_write_handle,
		(void*)0, 0);
	if (piped == FALSE) return -1;

	HANDLE remote_recv_handle;
	BOOL duplicated;
	duplicated = DuplicateHandle(
		GetCurrentProcess(),
		msg_read_handle,
		proc_handle,
		&remote_recv_handle,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	);
	if (!duplicated) return -2;

	HANDLE res_write_handle;
	HANDLE cmdr_read_handle;

	piped = CreatePipe(&cmdr_read_handle, &res_write_handle,
		(void*)0, 0);
	if (piped == FALSE) return -3;

	HANDLE remote_send_handle;
	duplicated = DuplicateHandle(
		GetCurrentProcess(),
		res_write_handle,
		proc_handle,
		&remote_send_handle,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	);
	if (!duplicated) return -4;

	struct _cmdr_params params;
	set_cmdr_funcs(&params);
	params.read_handle = remote_recv_handle;
	params.write_handle = remote_send_handle;

	struct _ztap_cmdr_pkg_t* pkg;
	pkg = calloc(1, sizeof(*pkg));
	if (pkg == 0) return -5;

	memcpy(&pkg->params, &params, sizeof(params));
	memcpy(&pkg->code_buf, _cmdr_thread, 0x1000);

	struct _ztap_cmdr_pkg_t* remote_pkg;
	remote_pkg = VirtualAllocEx(proc_handle, (void*)0,
		sizeof(*remote_pkg), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (remote_pkg == 0) return -6;

	BOOL wrote_properly;
	wrote_properly = WriteProcessMemory(proc_handle,
		remote_pkg, pkg, sizeof(*pkg), (void*)0);
	if (!wrote_properly) return -7;

	HANDLE thread_handle;
	thread_handle = CreateRemoteThread(proc_handle,
		(void*)0, 0, remote_pkg->code_buf,
		&remote_pkg->params, 0, 0);
	if (thread_handle == NULL) return -8;

	(*handle)->pipe_read = cmdr_read_handle;
	(*handle)->pipe_write = cmdr_write_handle;
	return 0;
}

BOOL ztap_cmdr_wpm(struct ztap_handle_t* handle,
				   void* base_address,
				   void* buffer,
				   size_t size,
				   size_t* out_size) {
	struct _cmdr_msg_t msg;
	struct _cmdr_wpm_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_wpm;
	params = &msg.params._cmdr_wpm_params;
	
	params->dest = base_address;
	params->buff_len = size;

	size_t sent;
	size_t total_sent;
	char* reading_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	sent = 0;
	total_sent = 0;
	reading_head = buffer;
	while (total_sent < size) {
		WriteFile(handle->pipe_write, reading_head,
			size, &sent, (void*)0);
		total_sent += sent;
		reading_head += sent;
	}
	*out_size = total_sent;
	
	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	return TRUE;
}

BOOL ztap_cmdr_rpm(struct ztap_handle_t* handle,
				   void* base_address,
				   void* buffer,
				   size_t size,
				   size_t* out_size) {
	struct _cmdr_msg_t msg;
	struct _cmdr_rpm_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_rpm;
	params = &msg.params._cmdr_rpm_params;

	params->src = base_address;
	params->buff_len = size;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	sent = 0;
	total_sent = 0;
	writing_head = buffer;
	while (total_sent < size) {
		ReadFile(handle->pipe_read, writing_head,
			size, &sent, (void*)0);
		total_sent += sent;
		writing_head += sent;
	}
	*out_size = total_sent;

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);
	return TRUE;

}

LPVOID ztap_cmdr_va(struct ztap_handle_t* handle,
				  void* address,
			 	  size_t size,
				  uint32_t allocation_type,
				  uint32_t  protect) {
	struct _cmdr_msg_t msg;
	struct _cmdr_va_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_va;
	params = &msg.params._cmdr_va_params;

	params->lpAddress = address;
	params->dwSize = size;
	params->flAllocationType = allocation_type;
	params->flProtect = protect;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);
	
	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);
	
	return res.val.ptr;
}

BOOL ztap_cmdr_vp(struct ztap_handle_t* handle,
				  void* address,
				  size_t size,
				  uint32_t new_protect,
				  uint32_t* old_protect) {
	struct _cmdr_msg_t msg;
	struct _cmdr_vp_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_vp;
	params = &msg.params._cmdr_vp_params;

	params->lpAddress = address;
	params->dwSize = size;
	params->flNewProtect = new_protect;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	if (res.res_type == DWORD_res_t) {
		*old_protect = res.val.dword;
		return TRUE;
	}
	else {
		handle->last_error = res.val.dword;
		return FALSE;
	}
}

BOOL ztap_cmdr_vf(struct ztap_handle_t* handle,
				  void* address,
				  size_t size,
				  uint32_t free_type) {
	struct _cmdr_msg_t msg;
	struct _cmdr_vf_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_vf;
	params = &msg.params._cmdr_vf_params;

	params->lpAddress = address;
	params->dwSize = size;
	params->dwFreeType = free_type;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	return res.val.bool;
}

HMODULE ztap_cmdr_lla(struct ztap_handle_t* handle,
					  char* lib_name) {
	struct _cmdr_msg_t msg;
	struct _cmdr_lla_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_lla;
	params = &msg.params._cmdr_lla_params;

	strcpy_s(&params->lpLibFilename, 255, lib_name);

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	return res.val.handle;
}

FARPROC ztap_cmdr_gpa(struct ztap_handle_t* handle,
				      HMODULE module_handle,
				      char* name) {
	struct _cmdr_msg_t msg;
	struct _cmdr_gpa_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_gpa;
	params = &msg.params._cmdr_gpa_params;

	params->hModule = module_handle;
	strcpy_s(&params->lpProcName, 255, name);

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	return res.val.farproc;
}

void ztap_cmdr_ct(struct ztap_handle_t* handle,
				 SECURITY_ATTRIBUTES* thread_attributes,
				 size_t stack_size,
				 void* start_address,
				 void* parameter,
				 DWORD creation_flags,
				 DWORD* thread_id) {
	struct _cmdr_msg_t msg;
	struct _cmdr_ct_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_ct;
	params = &msg.params._cmdr_ct_params;

	params->lpThreadAttributes = thread_attributes;
	params->dwStackSize = stack_size;
	params->lpStartAddress = start_address;
	params->lpParameter = parameter;
	params->dwCreationFlags = creation_flags;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	*thread_id = res.val.dword;
}

int ztap_cmdr_ncc(struct ztap_handle_t* handle,
				  char* start,
				  uint64_t size,
				  uint64_t range,
				  char** code_cave_ptr) {
	struct _cmdr_msg_t msg;
	struct _cmdr_ncc_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_ncc;
	params = &msg.params._cmdr_ncc_params;

	params->start = start;
	params->size = size;
	params->range = range;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	if (res.res_type == error_res_t) return -1;
	
	*code_cave_ptr = res.val.ptr;
	return 0;
}

int ztap_cmdr_fcc(struct ztap_handle_t* handle,
				  char* start,
				  uint64_t size,
				  char* end,
				  char** code_cave_ptr) {
	struct _cmdr_msg_t msg;
	struct _cmdr_fcc_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_fcc;
	params = &msg.params._cmdr_fcc_params;

	params->start = start;
	params->size = size;
	params->end = end;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);

	if (res.res_type == error_res_t) return -1;

	*code_cave_ptr = res.val.ptr;
	return 0;
}


void ztap_cmdr_end(struct ztap_handle_t* handle) {
	struct _cmdr_msg_t msg;
	struct _cmdr_fcc_params_t* params;

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = cmdr_end;
	params = &msg.params._cmdr_end_params;

	size_t sent;
	size_t total_sent;
	char* writing_head;

	WriteFile(handle->pipe_write, &msg,
		sizeof(msg), &sent, (void*)0);

	size_t res_recvd;
	struct _cmdr_res_t res;
	ReadFile(handle->pipe_read, &res, sizeof(res),
		&res_recvd, (void*)0);
}