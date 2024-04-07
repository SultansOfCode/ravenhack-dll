#include <Windows.h>

#include "utils.h"

LONG64 exe_section_address = 0;
LONG64 exe_section_size    = 0;

char zoom_hack_level            = 8;
char world_light_hack_level     = 255;
char world_light_hack_intensity = 215;

bool zoom_hack_enabled        = true;
bool world_light_hack_enabled = true;
bool cave_light_hack_enabled  = true;

void zoom_hack()
{
	char*  pattern      = (char*)"\x4C\x8B\xD1\xC6\x81\x92\x00\x00\x00\x01\x8B\x02\x89\x41\x48\x8B\x42\x04\x89\x41\x4C\x44\x8B\x02\x44\x8B\x4A\x04";
	LONG64 pattern_size = 28;
	LONG64 address      = search_memory(exe_section_address, exe_section_size, pattern, pattern_size);

	if (address == -1)
	{
		SHOW_ERROR("Could not find memory address");

		return;
	}

	char width    = 25 + zoom_hack_level * 2;
	char height   = 13 + zoom_hack_level * 2;
	char code[39] = { 0 };

	// MOV DWORD PTR DS:[RDX], WIDTH
	code[0] = '\xC7';
	code[1] = '\x02';
	code[2] = width;
	code[3] = '\x00';
	code[4] = '\x00';
	code[5] = '\x00';

	// MOV DWORD PTR DS:[RDX+0x4], HEIGHT
	code[6]  = '\xC7';
	code[7]  = '\x42';
	code[8]  = '\x04';
	code[9]  = height;
	code[10] = '\x00';
	code[11] = '\x00';
	code[12] = '\x00';

	// MOV EAX, DWORD PTR DS:[RDX]
	code[13] = '\x8B';
	code[14] = '\x02';

	// MOV DWORD PTR DS:[RCX+0x48], EAX
	code[15] = '\x89';
	code[16] = '\x41';
	code[17] = '\x48';

	// MOV EAX, DWORD PTR DS:[RDX+0x4]
	code[18] = '\x8B';
	code[19] = '\x42';
	code[20] = '\x04';

	// MOV DWORD PTR DS:[RCX+0x4C], EAX
	code[21] = '\x89';
	code[22] = '\x41';
	code[23] = '\x4C';

	// MOV R8D, DWORD PTR DS:[RDX]
	code[24] = '\x44';
	code[25] = '\x8B';
	code[26] = '\x02';

	LONG64 address_return = address + 0x18;

	// MOV RAX, &return
	code[27] = '\x48';
	code[28] = '\xB8';
	code[29] = (char)((address_return >>  0) & 0xFF);
	code[30] = (char)((address_return >>  8) & 0xFF);
	code[31] = (char)((address_return >> 16) & 0xFF);
	code[32] = (char)((address_return >> 24) & 0xFF);
	code[33] = (char)((address_return >> 32) & 0xFF);
	code[34] = (char)((address_return >> 40) & 0xFF);
	code[35] = (char)((address_return >> 48) & 0xFF);
	code[36] = (char)((address_return >> 56) & 0xFF);

	// JMP RAX
	code[37] = '\xFF';
	code[38] = '\xE0';

	LONG64 code_address = (LONG64)VirtualAlloc(0, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (code_address == NULL)
	{
		SHOW_ERROR("Could not allocate memory for code");

		return;
	}

	DWORD old_protection;

	VirtualProtect((LPVOID)code_address, sizeof(code), PAGE_EXECUTE_READWRITE, &old_protection);

	write_memory(code_address, code, sizeof(code));

	char   patch[14]     = { 0 };
	LONG64 patch_address = address + 0x0A;

	// MOV RAX, &code_address
	patch[0] = '\x48';
	patch[1] = '\xB8';
	patch[2] = (char)((code_address >>  0) & 0xFF);
	patch[3] = (char)((code_address >>  8) & 0xFF);
	patch[4] = (char)((code_address >> 16) & 0xFF);
	patch[5] = (char)((code_address >> 24) & 0xFF);
	patch[6] = (char)((code_address >> 32) & 0xFF);
	patch[7] = (char)((code_address >> 40) & 0xFF);
	patch[8] = (char)((code_address >> 48) & 0xFF);
	patch[9] = (char)((code_address >> 56) & 0xFF);

	// JMP RAX
	patch[10] = '\xFF';
	patch[11] = '\xE0';

	// NOPs
	patch[12] = '\x90';
	patch[13] = '\x90';

	VirtualProtect((LPVOID)exe_section_address, exe_section_size, PAGE_EXECUTE_READWRITE, &old_protection);

	write_memory(patch_address, patch, sizeof(patch));

	VirtualProtect((LPVOID)exe_section_address, exe_section_size, old_protection, &old_protection);
}

void world_light_hack()
{
	char*  pattern      = (char*)"\x8B\x45\xB0\x89\x05????\x8B\x45\xB4\x89\x05????\x0F\xB6\x45\xB8\x88\x05????\x0F\xB6\x45\xB9\x88\x05????";
	LONG64 pattern_size = 38;
	LONG64 address      = search_memory(exe_section_address, exe_section_size, pattern, pattern_size);

	if (address == -1)
	{
		SHOW_ERROR("Could not find memory address");

		return;
	}

	char   patch_intensity_code[4] = { 0 };
	LONG64 patch_intensity_address = address + 0x12;

	// MOV AL, world_light_hack_intensity
	patch_intensity_code[0] = '\xB0';
	patch_intensity_code[1] = world_light_hack_intensity;

	// NOPs
	patch_intensity_code[2] = '\x90';
	patch_intensity_code[3] = '\x90';

	char   patch_level_code[4] = { 0 };
	LONG64 patch_level_address = address + 0x1C;

	// MOV AL, world_light_hack_level
	patch_level_code[0] = '\xB0';
	patch_level_code[1] = world_light_hack_level;

	// NOPS
	patch_level_code[2] = '\x90';
	patch_level_code[3] = '\x90';

	DWORD old_protection;

	VirtualProtect((LPVOID)exe_section_address, exe_section_size, PAGE_EXECUTE_READWRITE, &old_protection);

	write_memory(patch_intensity_address, patch_intensity_code, sizeof(patch_intensity_code));
	write_memory(patch_level_address, patch_level_code, sizeof(patch_level_code));

	VirtualProtect((LPVOID)exe_section_address, exe_section_size, old_protection, &old_protection);
}

void cave_light_hack()
{
	char*  pattern      = (char*)"\xF3\x0F\x11\x45\x97\xF3\x0F\x11\x55\x9B\xF3\x0F\x58\xC8\xF3\x0F\x5C\xCE\xF3\x0F\x11\x4D\x9F\xF3\x0F\x58\xDA\xF3\x0F\x5C\xDE\xF3\x0F\x11\x5D\xA3\x80\x7D\xC7\x00";
	LONG64 pattern_size = 40;
	LONG64 address      = search_memory(exe_section_address, exe_section_size, pattern, pattern_size);

	if (address == -1)
	{
		SHOW_ERROR("Could not find memory address");

		return;
	}

	char   patch_code[1] = { 0 };
	LONG64 patch_address = address + 0x03;

	// Change from XMM0 to XMM1
	patch_code[0] = '\x4D';

	DWORD old_protection;

	VirtualProtect((LPVOID)exe_section_address, exe_section_size, PAGE_EXECUTE_READWRITE, &old_protection);

	write_memory(patch_address, patch_code, sizeof(patch_code));

	VirtualProtect((LPVOID)exe_section_address, exe_section_size, old_protection, &old_protection);
}

DWORD WINAPI main_thread(LPVOID param)
{
	get_executable_section(&exe_section_address, &exe_section_size);

	if (exe_section_address == 0 || exe_section_size == 0)
	{
		SHOW_ERROR("Could not find executable section");

		return 0;
	}

	zoom_hack_enabled        = (bool)read_ini_int("zoom_hack",        "enabled", 1);
	world_light_hack_enabled = (bool)read_ini_int("world_light_hack", "enabled", 1);
	cave_light_hack_enabled  = (bool)read_ini_int("cave_light_hack",  "enabled", 1);

	if (zoom_hack_enabled)
	{
		zoom_hack_level = (char)read_ini_int("zoom_hack", "level", 8);

		zoom_hack();
	}

	if (world_light_hack_enabled)
	{
		world_light_hack_level     = (char)read_ini_int("world_light_hack", "level",     255);
		world_light_hack_intensity = (char)read_ini_int("world_light_hack", "intensity", 215);

		world_light_hack();
	}

	if (cave_light_hack_enabled)
	{
		cave_light_hack();
	}

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, main_thread, hModule, 0, 0);
	}

	return TRUE;
}
