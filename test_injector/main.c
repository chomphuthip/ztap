#include<stdint.h>
#include<stdio.h>

#define _WIN32_LEAN_AND_MEAN
#include<Windows.h>
#include<TlHelp32.h>

#define _ztap_cringe_overoptimization
#include "ztap.h"

int disk(HANDLE proc_handle, HANDLE file_handle) {
	int res;
	res = ztap_disk(proc_handle, file_handle);

	CloseHandle(proc_handle);
	CloseHandle(file_handle);

	switch (res) {
	case 0:
		printf("Mapped\n");
		return 0;
	case -1:
		printf("Couldn't duplicate handle\n");
		return -1;
	case -2:
		printf("Couldn't allocate memory locally\n");
		return -1;
	case -3:
		printf("Couldn't allocate memory in target process\n");
		return -1;
	case -4:
		printf("Couldn't write to memory in target process\n");
		return -1;
	case -5:
		printf("Couldn't start thread in target process\n");
		return -1;
	}
}

int buff(HANDLE proc_handle, HANDLE file_handle) {
	HANDLE file_map;
	file_map = CreateFileMapping(file_handle,
		NULL, PAGE_READONLY, 0, 0, NULL);

	if (file_map == 0) {
		perror("Could't create file mapping\n");
		return -1;
	}

	char* file_view;
	file_view = MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0);

	int64_t file_len;
	GetFileSizeEx(file_handle, &file_len);

	int res;
	res = ztap_buff(proc_handle, file_view, file_len);

	CloseHandle(proc_handle);
	CloseHandle(file_handle);

	printf("%d\n", GetLastError());

	switch (res) {
	case 0:
		printf("Mapped\n");
		return 0;
	case -1:
		printf("Couldn't allocate memory locally\n");
		return -1;
	case -2:
		printf("Couldn't allocate memory in target process\n");
		return -1;
	case -3:
		printf("Couldn't write to memory in target process\n");
		return -1;
	case -4:
		printf("Couldn't start thread in target process\n");
		return -1;
	}
}

int pipe(HANDLE proc_handle, HANDLE file_handle) {
	HANDLE file_map;
	file_map = CreateFileMapping(file_handle,
		NULL, PAGE_READONLY, 0, 0, NULL);

	if (file_map == 0) {
		perror("Could't create file mapping\n");
		return -1;
	}

	char* file_view;
	file_view = MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0);

	int64_t file_len;
	GetFileSizeEx(file_handle, &file_len);

	int res;
	res = ztap_pipe(proc_handle, file_view, file_len);

	CloseHandle(proc_handle);
	CloseHandle(file_handle);

	printf("%d\n", GetLastError());

	switch (res) {
	case 0:
		printf("Mapped\n");
		return 0;
	case -1:
		printf("Couldn't allocate memory locally\n");
		return -1;
	case -2:
		printf("Couldn't allocate memory in target process\n");
		return -1;
	case -3:
		printf("Couldn't write to memory in target process\n");
		return -1;
	case -4:
		printf("Couldn't start thread in target process\n");
		return -1;
	}
}


int main(int argc, char** argv) {
	long proc_id;
	char* end;
	int err_code;

	err_code = 0;
	proc_id = strtol(argv[1], &end, 10);

	if (argc != 3 || end == argv[1]) {
		fprintf(stderr, "Usage: test_injector [proc id] [path to dll]");
		return -1;
	}

	HANDLE file_handle;
	file_handle = CreateFileA(
		argv[2],
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (file_handle == INVALID_HANDLE_VALUE) {
		perror("Unable to open file!\n");
		return -2;
	}

	TOKEN_PRIVILEGES priv;
	HANDLE token;
	memset(&priv, 0, sizeof(priv));
	token = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(token);
	}

	HANDLE proc_handle;
	proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);

	return pipe(proc_handle, file_handle);
}