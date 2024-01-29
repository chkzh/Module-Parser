#include "../include/parser.h"

#define TEST_EXE_1 "D://TraceMe.exe"
#define TEST_EXE_2 "D://CrackMe.exe"

PROCESS_INFORMATION g_pi;

int main()
{
	STARTUPINFOA sia;
	ZeroMemory(&sia, sizeof(sia));

	if (!CreateProcessA(TEST_EXE_2, NULL, NULL, NULL, false, 0, NULL, NULL, &sia, &g_pi)) {
		printf("[ERR] Create Process Failed..\n");
		return 0;
	}

	ModuleParser parser(g_pi.hProcess);

	Sleep(2000);

	parser.walkAddressSpace();
	parser.printModules();

	parser.queryModule("ntdll.dll");

	//ModuleInfo* p_info = parser.queryModule("user32.dll");
	//PVOID address = parser.getProcAddr(p_info, "MessageBoxA", NULL);
	//printf("Function address = %p\n", address);

	//ModuleInfo* p_exe = parser.exe_info();
	//printf("Exe Image Base = %p\n", p_exe->image_base);

	///* test export */
	//EdtIter iter(p_info, EdtIter::By_Name);
	//while (parser.ite(&iter))
	//{
	//	printf("%p  ", iter.addr_value);
	//	printf("%p  ", iter.location);
	//	printf("%s\n", iter.name.c_str());
	//}

	///* test import */
	//std::string last_importee;
	//IdtIter iter_2(p_exe);
	//while (parser.ite(&iter_2))
	//{
	//	if (last_importee != iter_2.importee_name)
	//	{
	//		printf("%s  ", iter_2.importee_name.c_str());

	//		if (parser.queryModule(iter_2.importee_name.c_str()) == NULL)
	//			printf("( not loaded )");

	//		printf("\n");

	//		last_importee = iter_2.importee_name;
	//	}

	//	printf("\t");
	//	printf("%p  ", iter_2.addr_value);
	//	printf("%p  ", iter_2.location);
	//	printf("%d  ", iter_2.oridinal);
	//	printf("%s  ", iter_2.name.c_str());

	//	printf("\n");
	//}

	//parser.printModules();

	return 0;
}