// dllmain.cpp : DLL uygulamasının giriş noktasını tanımlar.
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>

const DWORD BasePtr = 0x00F3690C;
const DWORD GenieBase = 0x568;

const DWORD Hook1Jmp1 = 0x008265C2;
const DWORD Hook1Jmp2 = 0x008267E1;

const DWORD Hook2Call1 = 0x008258A0;
const DWORD Hook2Call2 = 0x0040F800;
const DWORD Hook2Jmp1 = 0x0083040E;
DWORD Hook5Jmp1 = 0;

const DWORD dwHookAdr[5] = { 0x00826526 ,0x00830484 ,0x00825F63 ,0x00824DD8, 0x0082F4F6 };
const DWORD dwCountAdr[11] = { 0x00829AFC ,0x008258B5 ,0x00826963 ,0x0082489F ,0x00825D2C ,0x009A7BA9, 0x00824D92, 0x008248E3, 0x00824D21, 0x0082F5DE, 0x008283C0 };

DWORD getCallDiff(const DWORD Source, const DWORD Destination)
{
	DWORD Diff = 0;
	if (Source > Destination)
	{
		Diff = Source - Destination;
		if (Diff > 0)
		{
			return 0xFFFFFFFB - Diff;
		}
	}
	else
	{
		return Destination - Source - 5;
	}
	return 0;
}

void WritePatch(const DWORD pAdr, const BYTE* pPatch, const int pSize)
{
	DWORD pOld;

	if (VirtualProtect((void*)pAdr, pSize, PAGE_EXECUTE_READWRITE, &pOld))
	{
		memcpy((void*)pAdr, pPatch, pSize);
		VirtualProtect((void*)pAdr, pSize, pOld, 0);
	}
}


__declspec(naked) void Hook1()
{
	__asm
	{
		add eax, 0x14
		add ecx, 0x50
	}

LOOP:
	__asm
	{
		cmp [ecx], ebx
		je EXIT
		inc eax
		add ecx, 0x04
		cmp eax ,0x1C
		jb LOOP
		jmp Hook1Jmp2
		EXIT:
		jmp Hook1Jmp1
	}
}



__declspec(naked) void Hook2()
{
	__asm
	{
		add esi, 0x10
	}

		LOOP:
	__asm
	{
		push 0x00
		push esi
		push 0x15
		mov ecx, edi
		call Hook2Call1
		test eax, eax
		je EXIT
		push ebp
		push ebx
		mov ecx, eax
		call Hook2Call2
		test al, al
		jne SUCCESS
	}
		EXIT:
	__asm
	{
		inc esi
		cmp esi, 0x1C
		jb LOOP
		pop edi
		pop esi
		pop ebp
		xor al, al
		pop ebx
		pop ecx
		ret
	}
		SUCCESS:
	__asm
	{
		jmp Hook2Jmp1
	}
}

__declspec(naked) void Hook3()
{
	__asm
	{
		add esi, 0x10
	}

		LOOP:
	__asm
	{
		push 0x00
		push esi
		push 0x15
		mov ecx, edi
		call Hook2Call1
		test eax, eax
		je EXIT
		push ebp
		push ebx
		mov ecx, eax
		call Hook2Call2
		test al, al
		jne SUCCESS
	}

		EXIT:
	__asm
	{
		inc esi
		cmp esi, 0x1C
		jb LOOP
		pop edi
		pop esi
		pop ebp
		or eax, -01
		pop ebx
		ret
	}

		SUCCESS:
	__asm
	{
		pop edi
		mov eax, esi
		pop esi
		pop ebp
		pop ebx
		ret
	}
}


__declspec(naked) void Hook4()
{
	__asm
	{
		pushad
		xor esi, esi
		mov eax, BasePtr
		mov eax, [eax]
		add eax, GenieBase
		mov eax, [eax]
		add eax, 0x540 //24. Slot İlk Slot 0x4E0
		mov edi, eax
	}

	LOOP2:
	__asm
	{
		mov eax, [edi]
		test eax, eax
		je LOOP
		mov eax, [eax]
		test eax, eax
		je LOOP
		push 01
		mov edx, [eax]
		mov ecx, eax
		mov eax, [edx + 0x50]
		call eax
	}

    LOOP:
	__asm
	{
		inc esi
		add edi, 0x04
		cmp esi, 0x04
		jb LOOP2
		popad
		pop edi
		pop esi
		pop ebp
		ret 0x04
	}
}

__declspec(naked) void Hook5()
{
	__asm
	{
		add esi, 0x4e0
		mov edi, 0x1c
		jmp Hook5Jmp1
	}
}

void Init()
{
	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);

	std::cout << "Patch Start" << std::endl;

	BYTE o_Jmp[5] = { 0xE9 };
	DWORD dwFuncAdr[5] = { (DWORD)&Hook1, (DWORD)&Hook2 ,(DWORD)&Hook3 ,(DWORD)&Hook4, (DWORD)&Hook5 };

	Hook5Jmp1 = dwHookAdr[4] + 9;

	for(int i = 0; i < 5; i++)
	{
		*(DWORD*)(o_Jmp + 1) = getCallDiff(dwHookAdr[i], dwFuncAdr[i]);
		WritePatch(dwHookAdr[i], o_Jmp, sizeof(o_Jmp));
		std::cout << "HookSuccess(0x" << std::hex << dwHookAdr[i] << "-0x" << std::hex << dwFuncAdr[i] << ")" << std::endl;
	}

	BYTE o_Count = 0x1C;// Orjinali 0x18 +4 Ekliyoruz

	for(int i = 0; i < 11; i++)
	{
		if (i > 8)
			WritePatch(dwCountAdr[i] + 1, &o_Count, sizeof(o_Count));
		else
			WritePatch(dwCountAdr[i] + 2, &o_Count, sizeof(o_Count));

		std::cout << "Re counting 0x" << std::hex << dwCountAdr[i] << std::endl;
	}

	DWORD dwBase = *(DWORD*)(BasePtr);
	DWORD dwGenieBase = *(DWORD*)(dwBase + GenieBase);

	for(DWORD i = 0; i < 4; i++)
	{
		//0x540 24.Slot
		DWORD dwSlot = (dwGenieBase + 0x540) + (i * 4);
		*(DWORD*)(dwSlot) = 0;
		std::cout << "Clear Slot 0x" << std::hex << dwSlot << std::endl;
	}

	std::cout << "Patch End" << std::endl;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		Init();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

