#include "Memory.hpp"

namespace Memory
{
	namespace Assembly
	{
		enum class m_eOpcodeType : int
		{
			Unknown			= 0,
			Call			= 1,
			Jump_Near		= 2,
		};

		m_eOpcodeType GetOpcodeType(unsigned char* m_pBytes, int m_iSize)
		{
			switch (m_pBytes[0])
			{
				case 0x0F:
				{
					if (m_iSize >= 1 && m_pBytes[1] >= 0x80 && m_pBytes[1] <= 0x8F)
						return m_eOpcodeType::Jump_Near;
				}
				break;
				case 0xE8:
					return m_eOpcodeType::Call;
			}

			if (m_iSize == 0)
				return m_eOpcodeType::Unknown;
			
			return GetOpcodeType(&m_pBytes[1], m_iSize - 1);
		}

		uintptr_t ResolveCall(uintptr_t m_uAddress)
		{
			if (m_uAddress)
				return m_uAddress + *reinterpret_cast<int*>(m_uAddress + 0x1) + 0x5;

			return 0x0;
		}

		uintptr_t ResolveJumpNear(uintptr_t m_uAddress)
		{
			if (m_uAddress)
				return m_uAddress + *reinterpret_cast<int*>(m_uAddress + 0x2) + 0x6;

			return 0x0;
		}
	}

	unsigned char CharToValue(char m_cChar)
	{
		if (m_cChar >= '0' && '9' >= m_cChar) return m_cChar - '0';
		if (m_cChar >= 'A' && 'F' >= m_cChar) return m_cChar - 'A' + 0xA;
		return 0;
	}

	uintptr_t FindSignature(uintptr_t m_uAddress, uintptr_t m_uSize, const char* m_pSignature)
	{
		if (!m_uAddress || !m_uSize) return 0x0; // Ah man, imagine been null address.

		// Required data (128 bytes is enough if you're not retard)
		unsigned char m_uBytes[128]					= { 0 };
		unsigned char m_uMask[128]					= { 0 };

		// Special Parse Data
		int m_iPointerInSignature = -1;
		Assembly::m_eOpcodeType m_OpcodeToResolve	= Assembly::m_eOpcodeType::Unknown;
		bool m_bReadAfterResolve = false;
		
		// Parse to Bytes & Mask
		unsigned char* m_pBytesWrite	= m_uBytes;
		unsigned char* m_pMaskWrite		= m_uMask;
		while (1)
		{
			unsigned char m_uByte = static_cast<unsigned char>(*m_pSignature);
			if (m_uByte == '\0') break;
			if (m_uByte == ' ')
			{
				m_pSignature++;
				continue;
			}

			// Special Parse
			if (m_uByte == '*')
			{
				m_iPointerInSignature = static_cast<int>(m_pMaskWrite - m_uMask);
				m_pSignature++;
			}
			else if (m_uByte == '[' || m_uByte == ']')
			{
				m_bReadAfterResolve = (m_iPointerInSignature != -1);
				m_pSignature++;
			}
			else // Default Parse
			{
				if (m_uByte == '?')
				{
					if (*m_pSignature++ == '?')
						m_pSignature++;

					*m_pBytesWrite++ = 0;
					*m_pMaskWrite++ = '?';
				}
				else
				{
					*m_pBytesWrite++ = (CharToValue(*m_pSignature++) << 4) | (CharToValue(*m_pSignature++));
					*m_pMaskWrite++ = 'x';
				}
			}
		}
		if (m_iPointerInSignature != -1)
		{
			int m_iOpcodeToResolveIndex = max(0, m_iPointerInSignature - 3);
			m_OpcodeToResolve = Assembly::GetOpcodeType(&m_uBytes[m_iOpcodeToResolveIndex], m_iPointerInSignature - m_iOpcodeToResolveIndex - 1);
		}

		uintptr_t m_uReturnAddress = 0x0;
		uintptr_t m_uSignatureUsage	= static_cast<uintptr_t>(m_pMaskWrite - m_uMask) - 0x1;

		unsigned char* m_pAddressCheck = reinterpret_cast<unsigned char*>(m_uAddress);
		for (uintptr_t i = 0; (m_uSize - m_uSignatureUsage) > i; ++i)
		{
			for (uintptr_t m_uCheck = 0x0; m_uSignatureUsage >= m_uCheck; ++m_uCheck)
			{
				if (m_uSignatureUsage == m_uCheck)
				{
					m_uReturnAddress = reinterpret_cast<uintptr_t>(m_pAddressCheck);
					break;
				}
				if (m_uMask[m_uCheck] == '?') continue;

				if (m_uBytes[m_uCheck] != m_pAddressCheck[m_uCheck])
				{
					m_pAddressCheck += m_uCheck + 1;
					break;
				}
			}
			if (m_uReturnAddress)
			{
				switch (m_OpcodeToResolve)
				{
					default:
					{
						if (m_iPointerInSignature != -1)
							m_uReturnAddress = *reinterpret_cast<uintptr_t*>(m_uReturnAddress + m_iPointerInSignature);
					}
					break;
					case Assembly::m_eOpcodeType::Call:
						m_uReturnAddress = Assembly::ResolveCall(m_uReturnAddress + m_iPointerInSignature - 1);
						break;
					case Assembly::m_eOpcodeType::Jump_Near:
						m_uReturnAddress = Assembly::ResolveJumpNear(m_uReturnAddress + m_iPointerInSignature - 2);
						break;
				}

				if (m_bReadAfterResolve)
					m_uReturnAddress = *reinterpret_cast<uintptr_t*>(m_uReturnAddress);
			}
		}

		return m_uReturnAddress;
	}
}