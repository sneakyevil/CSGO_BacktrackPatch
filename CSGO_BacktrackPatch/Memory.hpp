#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Psapi.h>

namespace Memory
{
	class CModule
	{
	public:
		uintptr_t m_uAddress	= 0x0;
		uintptr_t m_uSize		= 0x0;

		CModule() { }
		CModule(const char* m_pModule)
		{
			HMODULE m_hModule = GetModuleHandleA(m_pModule);
			if (!m_hModule) return;

			MODULEINFO m_mInfo = { 0 };
			if (K32GetModuleInformation(reinterpret_cast<HANDLE>(-1), m_hModule, &m_mInfo, sizeof(MODULEINFO)))
			{
				m_uAddress	= reinterpret_cast<uintptr_t>(m_hModule);
				m_uSize		= static_cast<uintptr_t>(m_mInfo.SizeOfImage);
			}
		}
	};

	namespace Assembly
	{
		uintptr_t ResolveCall(uintptr_t m_uAddress);

		uintptr_t ResolveJumpNear(uintptr_t m_uAddress);
	}

	uintptr_t FindSignature(uintptr_t m_uAddress, uintptr_t m_uSize, const char* m_pSignature);

	static uintptr_t FindSignature(CModule& Module, const char* m_pSignature)
	{
		return FindSignature(Module.m_uAddress, Module.m_uSize, m_pSignature);
	}

	static uintptr_t FindSignature(const char* m_pModule, const char* m_pSignature)
	{
		CModule Module(m_pModule);
		return FindSignature(Module, m_pSignature);
	}
}