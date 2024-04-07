#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <string>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "User32.lib")

#define SHOW_ERROR(message) show_error(__FUNCTION__, __LINE__, (message));

char ini_path[MAX_PATH] = { 0 };

void show_error(const char* function, unsigned int line, const char* message)
{
	char line_buf[_MAX_ITOSTR_BASE10_COUNT] = { 0 };

	itoa(line, line_buf, 10);

	size_t error_message_size = (strlen(function) + strlen(line_buf) + strlen(message) + 5) * sizeof(char);
	char*  error_message      = (char*)malloc(error_message_size);

	memset(error_message, 0, error_message_size);

	sprintf(error_message, "[%s:%s] %s", function, line_buf, message);

	MessageBoxA(NULL, error_message, "Error", MB_ICONERROR | MB_OK);

	free(error_message);
}

void get_executable_section(LONG64* out_executable_address, LONG64* out_executable_size)
{
	*out_executable_address = 0;
	*out_executable_size    = 0;

	HMODULE h_mod = GetModuleHandle(NULL);

	if (h_mod == NULL)
	{
		return;
	}

	PIMAGE_NT_HEADERS64   nt_header    = ImageNtHeader(h_mod);
	WORD                  num_sections = nt_header->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section      = IMAGE_FIRST_SECTION(nt_header);

	for (WORD i = 0; i < num_sections; ++i)
	{
		if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
		{
			++section;

			continue;
		}

		*out_executable_address = section->VirtualAddress + (LONG64)h_mod;
		*out_executable_size    = section->SizeOfRawData;

		break;
	}
}

void get_main_thread_id(DWORD* out_main_thread_id)
{
	*out_main_thread_id = 0;

	DWORD     current_pid     = GetCurrentProcessId();
	ULONGLONG min_create_time = MAXULONGLONG;
	HANDLE    hThreadSnap     = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}

	THREADENTRY32 th32;

	th32.dwSize = sizeof(THREADENTRY32);

	BOOL bOK = TRUE;

	for (bOK = Thread32First(hThreadSnap, &th32); bOK; bOK = Thread32Next(hThreadSnap, &th32))
	{
		if (th32.th32OwnerProcessID != current_pid)
		{
			continue;
		}

		HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, th32.th32ThreadID);

		if (hThread == INVALID_HANDLE_VALUE)
		{
			continue;
		}

		FILETIME times[4] = { 0 };

		if (GetThreadTimes(hThread, &times[0], &times[1], &times[2], &times[3]))
		{
			ULONG64 time = ((ULONG64)(times[0].dwHighDateTime) << 32) + (times[0].dwLowDateTime & 0xFFFFFFFF);

			if (time && time < min_create_time)
			{
				min_create_time = time;

				*out_main_thread_id = th32.th32ThreadID;
			}
		}

		CloseHandle(hThread);
	}

	CloseHandle(hThreadSnap);
}

BOOL suspend_thread(DWORD thread_id)
{
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);

	if (thread_handle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD result = SuspendThread(thread_handle);

	CloseHandle(thread_handle);

	return (result != -1);
}

BOOL resume_thread(DWORD thread_id)
{
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);

	if (thread_handle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD result = ResumeThread(thread_handle);

	CloseHandle(thread_handle);

	return (result != -1);
}

LONG64 search_memory(LONG64 address, LONG64 size, char* pattern, LONG64 pattern_size)
{
	LONG64 memory_ptr    = address;
	size_t pattern_index = 0;

	while (memory_ptr < address + size)
	{
		char memory_byte  = *((char*)memory_ptr);
		char pattern_byte = *(pattern + pattern_index);

		if (memory_byte == pattern_byte || pattern_byte == '?')
		{
			++pattern_index;

			if (pattern_index == pattern_size)
			{
				return memory_ptr - pattern_size + 1;
			}
		}
		else
		{
			pattern_index = 0;
		}

		++memory_ptr;
	}

	return -1;
}

void write_memory(LONG64 address, char* buf, LONG64 size)
{
	for (LONG64 i = 0; i < size; ++i)
	{
		*((char*)(address + i)) = buf[i];
	}
}

unsigned int read_ini_int(const char* section, const char* key, unsigned int default_value)
{
	if (ini_path[0] == '\0')
	{
		HMODULE h_mod = NULL;

		if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&read_ini_int, &h_mod) == 0)
		{
			SHOW_ERROR("Could not get module handle for DLL");

			return default_value;
		}

		if (GetModuleFileNameA(h_mod, ini_path, sizeof(ini_path)) == 0)
		{
			SHOW_ERROR("Could not get module filename for DLL");

			return default_value;
		}

		size_t ini_path_size = strlen(ini_path);

		ini_path[ini_path_size - 3] = 'i';
		ini_path[ini_path_size - 2] = 'n';
		ini_path[ini_path_size - 1] = 'i';
	}

	return GetPrivateProfileIntA((LPCSTR)section, (LPCSTR)key, default_value, (LPCSTR)ini_path);
}
