#include "../include/parser.h"
#include <string.h>
#include <psapi.h>
#include <winternl.h>

#define errln(format,...) printf("[ERR]" format "\n",##__VA_ARGS__)
#define errln_ex(format,...) printf("[ERR %d]" format "\n",GetLastError(),##__VA_ARGS__)

#define RVA_DOS_NtHeader 0x3C
#define DOS_MAGIC 0x5A4D

ModuleParser::ModuleParser(HANDLE hProc)
{
	this->is_ok = true;
	this->ProcType = 0;
	this->ProcHandle = hProc;
	this->ExeImageBase = NULL;

	BOOL result = false;
	BOOL is_target_wow64;
	BOOL is_me_wow64;
	result = IsWow64Process(hProc, &is_target_wow64);
	result = result && IsWow64Process(GetCurrentProcess(), &is_me_wow64);
	if (result == false)
		this->is_ok = false;
	else if (is_target_wow64 == false && is_me_wow64 == true)
		this->is_ok = false;

	if (this->is_ok == false)
		errln("don't support target process type!");
}

void ModuleParser::reset(HANDLE hProc)
{
	this->is_ok = true;
	this->ProcType = 0;
	this->ProcHandle = hProc;
	this->ExeImageBase = NULL;

	// this->ApiInfoBook.clear();
	this->ModuleInfoBook.clear();

	BOOL result = false;
	BOOL is_target_wow64;
	BOOL is_me_wow64;
	result = IsWow64Process(hProc, &is_target_wow64);
	result = result && IsWow64Process(GetCurrentProcess(), &is_me_wow64);
	if (result == false)
		this->is_ok = false;
	else if (is_target_wow64 == false && is_me_wow64 == true)
		this->is_ok = false;

	if (this->is_ok == false)
		errln("don't support target process type!");
}

bool ModuleParser::is_supported()
{
	return this->is_ok;
}

ModuleInfo* ModuleParser::exe_info()
{
	auto ite = this->ModuleInfoBook.find(this->ExeImageBase);
	if (ite != this->ModuleInfoBook.end())
		return &(ite->second);
	else
		return NULL;
}

ModuleInfo* ModuleParser::queryModule(PVOID Addr)
{
	auto ite = this->ModuleInfoBook.begin();
	while (ite != this->ModuleInfoBook.end())
	{
		if (ite->second.image_base <= Addr &&
			(PCHAR)ite->second.image_base + ite->second.module_size > Addr)
			return &(ite->second);

		ite++;
	}

	return NULL;
}

ModuleInfo* ModuleParser::queryModule(const char* lpModuleName)
{
	int len;
	wchar_t* buff;
	ModuleInfo* p_info;
	len = MultiByteToWideChar(CP_UTF8, 0, lpModuleName, -1, NULL, 0);
	buff = new wchar_t[len];
	MultiByteToWideChar(CP_UTF8, 0, lpModuleName, -1, buff, len);
	p_info = this->queryModule(buff);
	delete[] buff;
	return p_info;
}

ModuleInfo* ModuleParser::queryModule(const wchar_t* lpModuleName)
{
	auto ite = this->ModuleInfoBook.begin();
	while (ite != this->ModuleInfoBook.end())
	{
		if (!_wcsicmp(lpModuleName, ite->second.name.c_str()))
			return &(ite->second);

		ite++;
	}

	return NULL;
}

//API_INFO* ModuleParser::queryApi(PVOID addr)
//{
//	auto ite = this->ApiInfoBook.find(addr);
//	if (ite != this->ApiInfoBook.end())
//		return &(ite->second);
//	else
//		return NULL;
//}

bool ModuleParser::walkAddressSpace()
{
	if (this->is_ok == false)
		return false;

	this->ModuleInfoBook.clear();

	/* get system page size */
	SYSTEM_INFO sys_info;
	ZeroMemory(&sys_info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&sys_info);

	/* walk user address space */
	SIZE_T query_result;
	MEMORY_BASIC_INFORMATION mem_basic_info;
	PVOID address = sys_info.lpMinimumApplicationAddress;
	while (address < sys_info.lpMaximumApplicationAddress)
	{
		ZeroMemory(&mem_basic_info, sizeof(MEMORY_BASIC_INFORMATION));
		query_result = VirtualQueryEx(this->ProcHandle, address, &mem_basic_info, sizeof(MEMORY_BASIC_INFORMATION));
		if (query_result == 0)
		{
			errln_ex("VirtualQueryEx failed, address = %p", address);
			return false;
		}

		/* normal cases */
		switch (mem_basic_info.State)
		{
		case MEM_FREE:
		case MEM_RESERVE:
			address = (PUCHAR)address + mem_basic_info.RegionSize;
			break;
		case MEM_COMMIT:

			/* image file reigon? */
			if (mem_basic_info.Type == MEM_IMAGE) {

				ModuleInfo* p_info = this->tryAddModule(mem_basic_info.BaseAddress, NULL);

				if (p_info) {
					address = (PCHAR)address + p_info->module_size;
					break;
				}
			}
			address = (PUCHAR)address + mem_basic_info.RegionSize;
			break;
		default:
			break;
		}
	}

	return true;
}

void ModuleParser::printModules()
{
	if (this->ModuleInfoBook.empty())
		printf("No module\n");

	auto ite_h = this->ModuleInfoBook.begin();
	while (ite_h != this->ModuleInfoBook.end()) {

		printf("%p  ", ite_h->second.image_base);
		printf("%d  ", ite_h->second.pe_type);
		printf("%d  ", ite_h->second.module_type);
		printf("%ls\n", ite_h->second.name.c_str());
		printf("path: %ls\n", ite_h->second.path.c_str());

		printf("\n");

		ite_h++;
	}
}

PVOID ModuleParser::getProcAddr(ModuleInfo* p_mod, const char* func_name, PVOID* export_locate)
{
	if (p_mod == NULL)
		return NULL;

	if (func_name == NULL)
		return NULL;

	PVOID dll_image_base = p_mod->image_base;

	//ModuleInfo* p_mod = this->tryAddModule(dll_image_base, NULL);
	//if (!p_mod)
	//	return NULL;

	PIMAGE_EXPORT_DIRECTORY p_export_table = (PIMAGE_EXPORT_DIRECTORY)p_mod->edt_addr;
	IMAGE_EXPORT_DIRECTORY export_table;
	PDWORD p_function_table_base;
	PDWORD p_name_table_base;	//名称数组
	PWORD p_name_oridinal_base;	//名称转索引数组

	ReadProcessMemory(this->ProcHandle, p_export_table, &export_table, sizeof(export_table), NULL);

	p_function_table_base = (PDWORD)((PUCHAR)dll_image_base + export_table.AddressOfFunctions);
	p_name_table_base = (PDWORD)((PUCHAR)dll_image_base + export_table.AddressOfNames);
	p_name_oridinal_base = (PWORD)((PUCHAR)dll_image_base + export_table.AddressOfNameOrdinals);

	DWORD high = export_table.NumberOfNames - 1;
	DWORD low = 0;
	DWORD middle;
	std::string cur_func_name;
	PVOID p_cur_function;
	DWORD cur_function_rva;
	while (high >= low)
	{
		middle = (high + low) >> 1;

		_read(p_name_table_base + middle, &cur_function_rva, sizeof(DWORD));

		p_cur_function = (PUCHAR)dll_image_base + cur_function_rva;
		this->_readString((PUCHAR)p_cur_function, cur_func_name);
		int result = strcmp(func_name, cur_func_name.c_str());
		if (result < 0)
			high = middle - 1;
		else if (result > 0)
			low = middle + 1;
		else
			break;
	}

	/* we found the function */
	if (high >= low)
	{
		WORD cur_index;
		_read(p_name_oridinal_base + middle, &cur_index, sizeof(WORD));

		PVOID location = p_function_table_base + cur_index;
		DWORD function_rva;
		_read(location, &function_rva, sizeof(DWORD));
		if (export_locate)
			*export_locate = location;

		PUCHAR real_address = function_rva + (PUCHAR)dll_image_base;

		/* add api */
		//this->tryAddApi(real_address, func_name, -1, NULL);

		return real_address;
	}
	else
	{
		errln_ex("Try to get proc address, but failed.");
	}

	if (export_locate)
		*export_locate = NULL;
	return NULL;
}

PVOID ModuleParser::getProcAddr(ModuleInfo* p_mod, DWORD oridinal, PVOID* export_table_addr)
{
	if (p_mod == NULL)
		return NULL;

	PVOID dll_image_base = p_mod->image_base;

	PIMAGE_EXPORT_DIRECTORY p_export_table = (PIMAGE_EXPORT_DIRECTORY)p_mod->edt_addr;
	IMAGE_EXPORT_DIRECTORY export_table;
	PDWORD p_function_table_base;
	//PDWORD p_name_table_base;
	//PWORD p_name_oridinal_base;

	_read(p_export_table, &export_table, sizeof(IMAGE_EXPORT_DIRECTORY));

	p_function_table_base = (PDWORD)((PUCHAR)dll_image_base + export_table.AddressOfFunctions);
	DWORD index = oridinal - export_table.Base;

	if (index >= export_table.AddressOfFunctions)
	{
		errln("Get proc address failed, oridinary out of index");
		return NULL;
	}

	PVOID entry_location = p_function_table_base + index;
	DWORD func_rva;
	_read(entry_location, &func_rva, sizeof(DWORD));

	if (export_table_addr)
		*export_table_addr = entry_location;

	PUCHAR real_address = func_rva + (PUCHAR)dll_image_base;

	/* add api */
	//this->tryAddApi(real_address, NULL, oridinal, NULL);

	return real_address;
}

bool ModuleParser::_read(PVOID Address, PVOID lpBuffer, DWORD BytesToRead)
{
	bool result = ReadProcessMemory(this->ProcHandle, Address, lpBuffer, BytesToRead, NULL);
	if (result == false)
		errln_ex("failed to read process memory!");

	return result;
}

void ModuleParser::_readString(PVOID StrAddr, std::string& str)
{
	str.clear();

	int i;
	char temp[0x20] = { 0 };
	do {
		_read(StrAddr, temp, 0x20);

		for (i = 0; i < 0x20; i++)
		{
			if (temp[i] > 126 && temp[i] < 32 && str.size() >= MAX_PATH)
			{
				str.clear();
				goto StopRead;
			}

			if (temp[i])
				str.push_back(temp[i]);
			else
				goto StopRead;
		}

		StrAddr = (PUCHAR)StrAddr + 0x20;

	} while (1);

StopRead:
	if (str.size() == 0)
		str = "[That isn't a string]";

	return;
}

bool ModuleParser::_parseAsPeHeader32(HANDLE hModule, ModuleInfo* info_slot)
{
	WORD dos_magic;
	if (_read(hModule, &dos_magic, sizeof(WORD)) == false ||
		dos_magic != DOS_MAGIC) {

		errln_ex("bad pe format");
		return false;
	}

	DWORD nt_rva;
	PVOID p_nt_header;
	if (!_read((PCHAR)hModule + RVA_DOS_NtHeader, &nt_rva, sizeof(DWORD)))
		return false;
	p_nt_header = (PCHAR)hModule + nt_rva;

	WORD optional_magic;
	if (!_read((PCHAR)p_nt_header + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD), &optional_magic, sizeof(WORD)))
		return false;

	if (optional_magic != 0x10B)
		return false;

	/* Ok, now we know this is a corrent module */
	IMAGE_NT_HEADERS32 nt_hd32;
	_read(p_nt_header, &nt_hd32, sizeof(IMAGE_NT_HEADERS32));

	info_slot->pe_type = 32;
	info_slot->module_size = nt_hd32.OptionalHeader.SizeOfImage;
	info_slot->section_count = nt_hd32.FileHeader.NumberOfSections;
	
	if (nt_hd32.FileHeader.Characteristics & IMAGE_FILE_DLL)
		info_slot->module_type = ModuleParser::Dll;
	else
		info_slot->module_type = ModuleParser::Exe;

	info_slot->image_base = hModule;
	info_slot->p_nt_hd = p_nt_header;
	info_slot->main_entry = nt_hd32.OptionalHeader.ImageBase + (PUCHAR)hModule;
	info_slot->idt_addr = nt_hd32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (PUCHAR)hModule;
	info_slot->edt_addr = nt_hd32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (PUCHAR)hModule;
	info_slot->section_header_addr = sizeof(IMAGE_NT_HEADERS32) + (PUCHAR)p_nt_header;

	return true;
}

bool ModuleParser::_parseAsPeHeader64(HANDLE hModule, ModuleInfo* info_slot)
{
	/* x86 can't parse x64 modules */
	if (!is_ok)
		return false;

	WORD dos_magic;
	if (_read(hModule, &dos_magic, sizeof(WORD)) == false ||
		dos_magic != DOS_MAGIC) {

		errln_ex("bad pe format");
		return false;
	}

	DWORD nt_rva;
	PVOID p_nt_header;
	if (!_read((PCHAR)hModule + RVA_DOS_NtHeader, &nt_rva, sizeof(DWORD)))
		return false;
	p_nt_header = (PCHAR)hModule + nt_rva;

	WORD optional_magic;
	if (!_read((PCHAR)p_nt_header + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD), &optional_magic, sizeof(WORD)))
		return false;

	if (optional_magic != 0x20B)
		return false;

	/* Ok, now we know this is a corrent module */
	IMAGE_NT_HEADERS64 nt_hd32;
	_read(p_nt_header, &nt_hd32, sizeof(IMAGE_NT_HEADERS64));

	info_slot->pe_type = 64;
	info_slot->module_size = nt_hd32.OptionalHeader.SizeOfImage;
	info_slot->section_count = nt_hd32.FileHeader.NumberOfSections;

	if (nt_hd32.FileHeader.Characteristics & IMAGE_FILE_DLL)
		info_slot->module_type = ModuleParser::Dll;
	else
		info_slot->module_type = ModuleParser::Exe;

	info_slot->image_base = hModule;
	info_slot->p_nt_hd = p_nt_header;
	info_slot->main_entry = nt_hd32.OptionalHeader.ImageBase + (PUCHAR)hModule;
	info_slot->idt_addr = nt_hd32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (PUCHAR)hModule;
	info_slot->edt_addr = nt_hd32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (PUCHAR)hModule;
	info_slot->section_header_addr = sizeof(IMAGE_NT_HEADERS64) + (PUCHAR)p_nt_header;

	return true;
}

ModuleInfo* ModuleParser::tryAddModule(PVOID ImageBase, bool* is_added_this_time)
{
	if (this->is_ok == false)
		return NULL;

	if (is_added_this_time)
		*is_added_this_time = false;

	auto ite_h = this->ModuleInfoBook.find(ImageBase);
	if (ite_h != this->ModuleInfoBook.end())
		return &(ite_h->second);

	if (is_added_this_time)
		*is_added_this_time = true;

	/* module is missing now try add module */
	ModuleInfo info;
	if (_parseAsPeHeader32(ImageBase, &info) == false && 
		_parseAsPeHeader64(ImageBase, &info) == false)
			return NULL;	// <-- maybe this isn't a module

	/* check if Exe Image Base is found */
	if (!this->ExeImageBase &&
		info.module_type == ModuleParser::Exe)
		this->ExeImageBase = ImageBase;

	/* now we need to get file name and path */
	wchar_t* lp_name_str;
	GetMappedFileNameW(this->ProcHandle, ImageBase, this->TempPath, MAX_PATH);
	if ((lp_name_str = wcsrchr(this->TempPath, L'\\')) == NULL &&
		(lp_name_str = wcsrchr(this->TempPath, L'/')) == NULL) {
		lp_name_str = this->TempPath;
	}
	else {
		lp_name_str++;
	}
	info.path = this->TempPath;
	info.name = lp_name_str;

	this->ModuleInfoBook.emplace(ImageBase, info);

	ite_h = this->ModuleInfoBook.find(ImageBase);

	return &(ite_h->second);
}