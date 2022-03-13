#include <Windows.h>
#include <stdio.h>

#include "MinHook/MinHook.h"
#include "Memory.hpp"

#define PRINT_PREFIX_ "[CSGO_BacktrackPatch] "

class CBasePlayer
{
public:
    uintptr_t GetNetworkProperty()
    {
        return *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(this) + 0x1C);
    }
};

namespace NetworkProperty
{
    uintptr_t m_uAddress = 0U;

    int GetEntityIndex(CBasePlayer* m_pPlayer)
    {
        uintptr_t m_uPlayerNetworkProperty = m_pPlayer->GetNetworkProperty();
        if (!m_uPlayerNetworkProperty) return -1;

        uintptr_t m_uAlloc = *reinterpret_cast<uintptr_t*>(m_uAddress);
        if (!m_uAlloc) return -1;

        // server.dll - xref string (entindex_killed)
        return (m_uPlayerNetworkProperty - *reinterpret_cast<uintptr_t*>(m_uAlloc + 0x60)) >> 4;
    }
}

#define IN_ATTACK		(1 << 0)

class CUserCmd
{
public:
    virtual ~CUserCmd() { };
	// For matching server and client commands for debugging
	int		command_number;
	// the tick the client created this command
	int		tick_count;

	// Player instantaneous view angles.
	float	viewangles[3];
	float	aimdirection[3];	// For pointing devices. 
	// Intended velocities
	//	forward velocity.
	float	forwardmove;
	//  sideways velocity.
	float	sidemove;
	//  upward velocity.
	float	upmove;
	// Attack button states
	int		buttons;
	// Impulse command issued.
	byte    impulse;
	// Current weapon id
	int		weaponselect;
	int		weaponsubtype;
	int		random_seed;	// For shared random functions
	int		server_random_seed; // Only the server populates this seed
	short	mousedx;		// mouse accum in x from create move
	short	mousedy;		// mouse accum in y from create move
	bool	hasbeenpredicted;
};

#define MAX_PLAYERS 64

#define DELTA_TICKS     64 // if new tick +/- old tick is above this delta we assume its new player/dropped packets
#define MAX_TICKS       32 // how much ticks we store
class CBacktrackPatch
{
public:
    int m_iLastTick = -1;
    int m_iLasts[MAX_TICKS] = { 0 };
    int m_iLastIndex = 0;

    CBacktrackPatch() { }

    void ClearTicks()
    {
        memset(m_iLasts, 0, (MAX_TICKS * 4));
    }

    int GetHighest()
    {
        int m_iReturn = -1;

        for (int i : m_iLasts)
        {
            if (i > m_iReturn) m_iReturn = i;
        }

        return m_iReturn;
    }

    bool Exist(int m_iTickCount)
    {
        for (int i : m_iLasts)
        {
            if (i == m_iTickCount) return true;
        }

        return false;
    }

    void WriteTick(int m_iTickCount)
    {
        m_iLastTick = m_iTickCount;
        m_iLasts[m_iLastIndex] = m_iTickCount;

        ++m_iLastIndex;
        if (m_iLastIndex >= MAX_TICKS) m_iLastIndex = 0;
    }
};

namespace CPlayerMove
{
    CBacktrackPatch BacktrackPatch[MAX_PLAYERS + 1];

    typedef void(__fastcall* m_tRunCommand)(void*, void*, CBasePlayer*, CUserCmd*, void*); m_tRunCommand m_oRunCommand;
    void __fastcall RunCommand(void* ecx, void* edx, CBasePlayer* m_pPlayer, CUserCmd* m_pCMD, void* m_pMoveHelper)
    {
        int m_iIndex = NetworkProperty::GetEntityIndex(m_pPlayer);
        if (m_iIndex >= 1 && m_iIndex <= MAX_PLAYERS) // IsPlayer
        {
            int m_iCurrentTickCount = m_pCMD->tick_count;

            CBacktrackPatch* m_pPatch = &BacktrackPatch[m_iIndex];
            if (m_pCMD->buttons & IN_ATTACK) // We check only IN_ATTACK (this is important!)
            {
                if (m_pPatch->Exist(m_iCurrentTickCount)) // If current tick exist in history
                {
                    int m_iHighestTickHistory = m_pPatch->GetHighest();
                    if (m_iHighestTickHistory > m_iCurrentTickCount) // New tick is lower than highest tick in history
                    {
                        printf(PRINT_PREFIX_"Player %d# tried to use old tickcount (cur: %d | highest %d)\n", m_iIndex, m_iCurrentTickCount, m_iHighestTickHistory);
                        return; // Don't process this command is attempt for backtrack.
                        /*
                        *   If Valve bothers do something I would rather just run the command but I would probably replace the tick_count for "predicted" new one from last
                        *   so the actual user still tries to shot the hitbox he see, if this was even accidental.
                        * 
                        *   ex: m_pCMD->tick_count = m_pPatch->m_iLastTick + 1;
                        */
                    }
                }
            }
            else if (m_iCurrentTickCount > (m_pPatch->m_iLastTick + DELTA_TICKS) || (m_pPatch->m_iLastTick - DELTA_TICKS) > m_iCurrentTickCount) // Big delta so we clear for now...
                m_pPatch->ClearTicks();

            m_pPatch->WriteTick(m_iCurrentTickCount);
        }

        m_oRunCommand(ecx, edx, m_pPlayer, m_pCMD, m_pMoveHelper);
    }
}

bool TryHook(uintptr_t m_uFunction, void* m_pHook, void** m_pOriginal = nullptr)
{
    void* m_pFunction = reinterpret_cast<void*>(m_uFunction);

    if (m_pFunction && MH_CreateHook(m_pFunction, m_pHook, m_pOriginal) == MH_OK)
    {
        MH_EnableHook(m_pFunction);
        return true;
    }

    return false;
}

FILE* m_pConsole = nullptr;
DWORD __stdcall Thread(void* m_pReserved)
{
    Memory::CModule m_Server("server.dll");
    if (m_Server.m_uAddress)
    {
        MH_Initialize();

        {
            NetworkProperty::m_uAddress = Memory::FindSignature(m_Server, "A1 *? ? ? ? 0F 5B C0 F3 0F 58 87");
            if (NetworkProperty::m_uAddress)
            {
                if (!TryHook(Memory::FindSignature(m_Server, "55 8B EC 83 E4 F8 83 EC 34 53 56 8B 75 08"), CPlayerMove::RunCommand, (void**)&CPlayerMove::m_oRunCommand))
                    printf(PRINT_PREFIX_"CPlayerMove::RunCommand - failed to hook\n");
            }
            else
                printf(PRINT_PREFIX_"NetworkProperty - address is null\n");
        }

        static bool m_bUnload = false;
        while (!m_bUnload) Sleep(1);

        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    else
        printf(PRINT_PREFIX_"server.dll is not loaded!\n");

    printf(PRINT_PREFIX_"Unloading...\n\n\n");
    if (m_pConsole)
    {
        fclose(m_pConsole);
        FreeConsole();
    }
    FreeLibraryAndExitThread(reinterpret_cast<HMODULE>(m_pReserved), 0x0);

    return 0x0;
}

int __stdcall DllMain(HMODULE m_hModule, DWORD m_dReason, void* m_pReserved)
{
    if (m_dReason == DLL_PROCESS_ATTACH)
    {
        if (AllocConsole())
        {
            freopen_s(&m_pConsole, "CONOUT$", "w", stdout);
            printf(PRINT_PREFIX_"Successfully injected!\n");
        }

        CreateThread(0, 0, Thread, m_hModule, 0, 0);
    }

    return 1;
}
