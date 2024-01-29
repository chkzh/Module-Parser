#include "../include/parser.h"

/* false = reached ite end */
bool ModuleParser::ite(ModIter* iter)
{
	//if (this->is_ok == false)
	//	return false;

	switch (iter->type()) {
	
	case ModIter::Edt_Ite:
		return this->_ite_edt((EdtIter*)iter);

	case ModIter::Idt_Ite:

		if (iter->targ()->pe_type == 32)
			return this->_ite_idt_32((IdtIter*)iter);
		else
			return this->_ite_idt_64((IdtIter*)iter);
	}

	return false;
}

bool ModuleParser::_ite_edt(EdtIter* iter)
{
	ModuleInfo* p_info = iter->targ();

	/* fix up all stuff */
	if (iter->_inited == false) {
		
		PIMAGE_EXPORT_DIRECTORY p_edt = (PIMAGE_EXPORT_DIRECTORY)p_info->edt_addr;
		IMAGE_EXPORT_DIRECTORY edt;
		
		this->_read(p_edt, &edt, sizeof(edt));

		iter->_cur_index = 0;
		iter->_name_count = edt.NumberOfNames;
		iter->_export_count = edt.NumberOfFunctions;

		iter->_name_ptr = (PDWORD)((PCHAR)p_info->image_base + edt.AddressOfNames);
		iter->_name_to_id_ptr = (PWORD)((PCHAR)p_info->image_base + edt.AddressOfNameOrdinals);
		iter->_rva_ptr = (PDWORD)((PCHAR)p_info->image_base + edt.AddressOfFunctions);

		iter->_base = edt.Base;

		iter->_inited = true;
	}

	/* now we iterate */
	if (iter->_edt_type == EdtIter::By_Name) {

		/* the end */
		if (iter->_cur_index >= iter->_name_count)
			return false;

		/* not the end */
		WORD id;
		DWORD rva;
		DWORD name_rva;
		PDWORD p_name_rva = iter->_name_ptr + iter->_cur_index;
		PWORD p_id = iter->_name_to_id_ptr + iter->_cur_index;
		PDWORD p_rva;
		PVOID p_name;

		this->_read(p_id, &id, sizeof(WORD));
		this->_read(p_name_rva, &name_rva, sizeof(DWORD));

		p_name = (PCHAR)p_info->image_base + name_rva;
		p_rva = iter->_rva_ptr + id;

		this->_read(p_rva, &rva, sizeof(DWORD));

		/* fill info */
		iter->addr_value = (PCHAR)p_info->image_base + rva;
		iter->location = p_rva;
		this->_readString(p_name, iter->name);

		iter->_cur_index++;

		return true;
	}
	else if (iter->_edt_type == EdtIter::By_Oridinal) {

		/* the end */
		if (iter->_cur_index >= iter->_export_count)
			return false;

		DWORD rva_2;
		PDWORD p_rva_2 = iter->_rva_ptr + iter->_cur_index;

		this->_read(p_rva_2, &rva_2, sizeof(DWORD));

		/* fill info */
		iter->addr_value = (PCHAR)p_info->image_base + rva_2;
		iter->location = p_rva_2;
		iter->oridinal = iter->_base + iter->_cur_index;

		iter->_cur_index++;

		return true;
	}
		
	return false;
}

bool ModuleParser::_ite_idt_32(IdtIter* iter)
{
	ModuleInfo* p_info = iter->targ();

	/* fix up what we need */
	if (iter->_inited == false)
	{
		PIMAGE_IMPORT_DESCRIPTOR p_iid = (PIMAGE_IMPORT_DESCRIPTOR)p_info->idt_addr;
		IMAGE_IMPORT_DESCRIPTOR iid;

		this->_read(p_iid, &iid, sizeof(iid));

		if (iid.FirstThunk == NULL)
			return false;

		iter->_cur_entry_index = 0;
		iter->_cur_iid_index = 0;

		iter->_iid_ptr = p_iid;
		iter->_int_ptr = iid.OriginalFirstThunk + (PCHAR)p_info->image_base;
		iter->_iat_ptr = iid.FirstThunk + (PCHAR)p_info->image_base;

		this->_readString((PCHAR)p_info->image_base + iid.Name, iter->importee_name);

		iter->_inited = true;

	}

	/* now we iter */
	PIMAGE_THUNK_DATA32 p_iat, p_int;
	IMAGE_THUNK_DATA32 _iat, _int;

	p_iat = (PIMAGE_THUNK_DATA32)iter->_iat_ptr + iter->_cur_entry_index;
	p_int = (PIMAGE_THUNK_DATA32)iter->_int_ptr + iter->_cur_entry_index;

	this->_read(p_iat, &_iat, sizeof(_iat));
	this->_read(p_int, &_int, sizeof(_int));

	/* need load another iid */
	if (_iat.u1.Function == NULL)
	{
		PIMAGE_IMPORT_DESCRIPTOR p_iid_2 = iter->_iid_ptr + iter->_cur_iid_index;
		IMAGE_IMPORT_DESCRIPTOR iid_2;

		this->_read(p_iid_2, &iid_2, sizeof(iid_2));

		/* check end */
		if (iid_2.FirstThunk == NULL)
			return false;

		iter->_cur_iid_index++;

		iter->_int_ptr = iid_2.OriginalFirstThunk + (PCHAR)p_info->image_base;
		iter->_iat_ptr = iid_2.FirstThunk + (PCHAR)p_info->image_base;

		this->_readString((PCHAR)p_info->image_base + iid_2.Name, iter->importee_name);

		iter->_cur_entry_index = 0;

		p_iat = (PIMAGE_THUNK_DATA32)iter->_iat_ptr + iter->_cur_entry_index;
		p_int = (PIMAGE_THUNK_DATA32)iter->_int_ptr + iter->_cur_entry_index;

		this->_read(p_iat, &_iat, sizeof(_iat));
		this->_read(p_int, &_int, sizeof(_int));
	}

	/* now we got iat and int */
	iter->addr_value = (PVOID)_iat.u1.Function;
	iter->location = p_iat;

	if (_int.u1.Ordinal & IMAGE_ORDINAL_FLAG32)	// import by oridinal
	{
		iter->oridinal = _int.u1.Ordinal & ~IMAGE_ORDINAL_FLAG32;
		iter->name.clear();
	}
	else
	{
		this->_readString((PCHAR)p_info->image_base + _int.u1.AddressOfData + 2, iter->name);
		iter->oridinal = -1;
	}

	iter->_cur_entry_index++;

	return true;
}

bool ModuleParser::_ite_idt_64(IdtIter* iter)
{
	ModuleInfo* p_info = iter->targ();

	/* fix up what we need */
	if (iter->_inited == false)
	{
		PIMAGE_IMPORT_DESCRIPTOR p_iid = (PIMAGE_IMPORT_DESCRIPTOR)p_info->idt_addr;
		IMAGE_IMPORT_DESCRIPTOR iid;

		this->_read(p_iid, &iid, sizeof(iid));

		if (iid.FirstThunk == NULL)
			return false;

		iter->_cur_entry_index = 0;
		iter->_cur_iid_index = 0;

		iter->_iid_ptr = p_iid;
		iter->_int_ptr = iid.OriginalFirstThunk + (PCHAR)p_info->image_base;
		iter->_iat_ptr = iid.FirstThunk + (PCHAR)p_info->image_base;

		this->_readString((PCHAR)p_info->image_base + iid.Name, iter->importee_name);

		iter->_inited = true;

	}

	/* now we iter */
	PIMAGE_THUNK_DATA64 p_iat, p_int;
	IMAGE_THUNK_DATA64 _iat, _int;

	p_iat = (PIMAGE_THUNK_DATA64)iter->_iat_ptr + iter->_cur_entry_index;
	p_int = (PIMAGE_THUNK_DATA64)iter->_int_ptr + iter->_cur_entry_index;

	this->_read(p_iat, &_iat, sizeof(_iat));
	this->_read(p_int, &_int, sizeof(_int));

	/* need load another iid */
	if (_iat.u1.Function == NULL)
	{
		PIMAGE_IMPORT_DESCRIPTOR p_iid_2 = iter->_iid_ptr + iter->_cur_iid_index;
		IMAGE_IMPORT_DESCRIPTOR iid_2;

		this->_read(p_iid_2, &iid_2, sizeof(iid_2));

		/* check end */
		if (iid_2.FirstThunk == NULL)
			return false;

		iter->_cur_iid_index++;

		iter->_int_ptr = iid_2.OriginalFirstThunk + (PCHAR)p_info->image_base;
		iter->_iat_ptr = iid_2.FirstThunk + (PCHAR)p_info->image_base;

		this->_readString((PCHAR)p_info->image_base + iid_2.Name, iter->importee_name);

		iter->_cur_entry_index = 0;

		p_iat = (PIMAGE_THUNK_DATA64)iter->_iat_ptr + iter->_cur_entry_index;
		p_int = (PIMAGE_THUNK_DATA64)iter->_int_ptr + iter->_cur_entry_index;

		this->_read(p_iat, &_iat, sizeof(_iat));
		this->_read(p_int, &_int, sizeof(_int));
	}

	/* now we got iat and int */
	iter->addr_value = (PVOID)_iat.u1.Function;
	iter->location = p_iat;

	if (_int.u1.Ordinal & IMAGE_ORDINAL_FLAG64)	// import by oridinal
	{
		iter->oridinal = _int.u1.Ordinal & ~IMAGE_ORDINAL_FLAG64;
		iter->name.clear();
	}
	else
	{
		this->_readString((PCHAR)p_info->image_base + _int.u1.AddressOfData + 2, iter->name);
		iter->oridinal = -1;
	}

	iter->_cur_entry_index++;

	return true;
}