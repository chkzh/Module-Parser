#pragma once

#include <windows.h>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <winternl.h>

/*
	Idea - Iterator

	1. Idt
		module_to_ite - ModuleInfo
		current_module_handle - ModuleInfo
		module_id
		current_import_entry_address
		current_import_entry_oridinal
		current_import_entry_name
		current_import_entry_location
		import_entry_id
		
	2. Edt
		module_to_ite
		ite_style
		base
		function_id
		function_name
		function_address
		export_entry_locate - PWORD

*/

//typedef struct
//{
//	PVOID ApiEntryAddress;
//	DWORD Oridinal;
//	std::string ApiName;
//}ApiInfo;

/* it means this module is parsed successfully */
typedef struct
{
	WORD pe_type;
	WORD module_type;
	DWORD section_count;
	DWORD module_size;
	
	PVOID image_base;
	PVOID p_nt_hd;
	PVOID main_entry;
	PVOID idt_addr;
	PVOID edt_addr;
	PVOID section_header_addr;
	
	std::wstring path;
	std::wstring name;

}ModuleInfo;

// =========================== SUB CLASS ======================== //

class ModuleParser;

class ModIter
{
	friend class ModuleParser;

protected:
	enum ITER_TYPE {
		Idt_Ite,
		Edt_Ite
	};

protected:
	bool _inited;
	ModuleInfo* _targ_mod;
	ITER_TYPE _ite_type;

public:

	ModIter(ModuleInfo* targ_info, ITER_TYPE type)
	{
		this->_inited = false;
		this->_targ_mod = targ_info;
		this->_ite_type = type;
	}

	ITER_TYPE type() {
		return this->_ite_type;
	}

	ModuleInfo* targ() {
		return this->_targ_mod;
	}

};

class IdtIter : public ModIter
{
	friend class ModuleParser;

private:
	DWORD _cur_iid_index;
	DWORD _cur_entry_index;
	PIMAGE_IMPORT_DESCRIPTOR _iid_ptr;
	PVOID _iat_ptr;
	PVOID _int_ptr;

public:
	std::string importee_name;

	DWORD oridinal;
	PVOID addr_value;
	PVOID location;
	std::string name;

	IdtIter(ModuleInfo* targ_info)
		:ModIter(targ_info, ModIter::Idt_Ite)
	{
		this->_cur_iid_index = -1;
		this->_cur_entry_index = -1;

		this->_iid_ptr = NULL;
		this->_iat_ptr = NULL;
		this->_int_ptr = NULL;

		this->oridinal = -1;
		this->addr_value = NULL;
		this->location = NULL;
	}
};

class EdtIter : public ModIter
{
	friend class ModuleParser;

public:
	enum EDT_TYPE {
		By_Name,
		By_Oridinal
	};

private:
	EDT_TYPE _edt_type;

	DWORD _cur_index;
	DWORD _name_count;
	DWORD _export_count;
	DWORD _base;
	PDWORD _name_ptr;		/* 名字数组 */
	PWORD _name_to_id_ptr;	/* 名字转ID数组 */
	PDWORD _rva_ptr;		/* 导出函数偏移数组 */

public:
	DWORD oridinal;
	PVOID addr_value;
	PVOID location;
	std::string name;

	EdtIter(ModuleInfo* info, EDT_TYPE edt_type)
		:ModIter(info, ModIter::Edt_Ite)
	{
		this->_edt_type = edt_type;

		this->_name_count = 0;
		this->_export_count = 0;
		this->_cur_index = -1;
		this->_base = -1;

		this->_name_ptr = NULL;
		this->_name_to_id_ptr = NULL;
		this->_rva_ptr = NULL;

		this->oridinal = -1;
		this->addr_value = NULL;
		this->location = NULL;
	}

	DWORD base() 
	{
		return this->_base;
	}

};

// ============================== MAIN MODULE ============================== //

/*

	x64: support x86 and x64
	x86: only support x86, try parsing x64 will get nothing

*/
class ModuleParser
{
private:
	bool is_ok;

	DWORD ProcType;
	HANDLE ProcHandle;
	PVOID ExeImageBase;

	wchar_t TempPath[MAX_PATH];
	// wchar_t TmpDstPath[MAX_PATH];

public:
	enum MODULE_TYPE {
		Exe = 0,
		Dll = 1
	};

	// std::map<PVOID, ApiInfo> ApiInfoBook;
	std::map<PVOID, ModuleInfo> ModuleInfoBook;

public:
	ModuleParser(HANDLE hProc);

	void reset(HANDLE hProc);

	bool is_supported();

	ModuleInfo* exe_info();

	ModuleInfo* queryModule(PVOID Addr);
	ModuleInfo* queryModule(const char* lpModuleName);
	ModuleInfo* queryModule(const wchar_t* lpModuleName);

	/* WRITE ModuleInfo */
	ModuleInfo* tryAddModule(PVOID ImageBase, bool* is_added_this_time);
	bool walkAddressSpace();

	void printModules();

	PVOID getProcAddr(ModuleInfo* p_mod, const char* func_name, PVOID* export_table_addr);
	PVOID getProcAddr(ModuleInfo* p_mod, DWORD oridinal, PVOID* export_table_addr);

	bool ite(ModIter* iter);

private:

	bool _read(PVOID Address, PVOID lpBuffer, DWORD BytesToRead);
	void _readString(PVOID addr, std::string& str);

	bool _parseAsPeHeader32(HANDLE hModule, ModuleInfo* info_slot);
	bool _parseAsPeHeader64(HANDLE hModule, ModuleInfo* inso_slot);

	bool _ite_idt_32(IdtIter* iter);
	bool _ite_idt_64(IdtIter* iter);
	bool _ite_edt(EdtIter* iter);
};