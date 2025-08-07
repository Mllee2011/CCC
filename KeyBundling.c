void MakeSubKey()
{
	unsigned char pRES[8];
	unsigned char pXOR[8];
	unsigned char pR64[8];
	unsigned char pInit[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B};
	unsigned char bTrue = 0;

	memset(m_pK1, 0x00, 8);
	memset(m_pK2, 0x00, 8);

	TripleDes(DES_ENCRYPT, m_pRND, m_pTMK, pRES, 0);

	if((pRES[0] & 0x80) == 0x80)
		bTrue = 1;

	memset(pXOR, 0x00, 8);
	memcpy(pR64, pRES, 8);
	memcpy(pXOR, pRES, 8);

	LeftShift(pXOR);

	if(bTrue == 1)
	{		
		XOR(pXOR, pInit, 8);
	}

	memcpy(m_pK1, pXOR, 8);

	DebugUSBMsg(debuglebel2,"MakeSubKey : K1 - %02X %02X %02X %02X %02X %02X %02X %02X\n", m_pK1[0], m_pK1[1], m_pK1[2], m_pK1[3], m_pK1[4], m_pK1[5], m_pK1[6], m_pK1[7]);

	bTrue = 0;
	memcpy(pRES, m_pK1, 8);
	if((pRES[0] & 0x80) == 0x80)
		bTrue = 1;

	memset(pXOR, 0x00, 8);
	memcpy(pR64, pRES, 8);
	memcpy(pXOR, pRES, 8);
	
	LeftShift(pXOR);

	if(bTrue == 1)
	{		
		XOR(pXOR, pInit, 8);
	}

	memcpy(m_pK2, pXOR, 8);

	DebugUSBMsg(debuglebel2,"MakeSubKey : K2 - %02X %02X %02X %02X %02X %02X %02X %02X\n", m_pK2[0], m_pK2[1], m_pK2[2], m_pK2[3], m_pK2[4], m_pK2[5], m_pK2[6], m_pK2[7]);
	
}

void MakeEncryptKey()
{	
	unsigned char pData1[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
	unsigned char	pData2[8] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
	unsigned char pRES[8];

	XOR(pData1, m_pK1, 8);

	TripleDes(DES_ENCRYPT, pData1, m_pTMK, pRES, 0);

	memcpy(m_pEncKey, pRES, 8);

	XOR(pData2, m_pK1, 8);

	TripleDes(DES_ENCRYPT, pData2, m_pTMK, pRES, 0);

	memcpy(m_pEncKey+8, pRES, 8);

	DebugUSBMsg(CERT_LEVEL,"MakeEncryptKey : %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", m_pEncKey[0], m_pEncKey[1], m_pEncKey[2], m_pEncKey[3], m_pEncKey[4], m_pEncKey[5], m_pEncKey[6], m_pEncKey[7], m_pEncKey[8], m_pEncKey[9], m_pEncKey[10], m_pEncKey[11], m_pEncKey[12], m_pEncKey[13], m_pEncKey[14], m_pEncKey[15]);
}

void MakeMACKey()
{
	unsigned char pData1[8] = {0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80};
	unsigned char pData2[8] = {0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80};
	unsigned char pRES[8];

	XOR(pData1, m_pK1, 8);

	TripleDes(DES_ENCRYPT, pData1, m_pTMK, pRES, 0);

	memcpy(m_pMACKey, pRES, 8);

	XOR(pData2, m_pK1, 8);

	TripleDes(DES_ENCRYPT, pData2, m_pTMK, pRES, 0);

	memcpy(m_pMACKey+8, pRES, 8);

	DebugUSBMsg(CERT_LEVEL,"MakeMACKey : %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", m_pMACKey[0], m_pMACKey[1], m_pMACKey[2], m_pMACKey[3], m_pMACKey[4], m_pMACKey[5], m_pMACKey[6], m_pMACKey[7], m_pMACKey[8], m_pMACKey[9], m_pMACKey[10], m_pMACKey[11], m_pMACKey[12], m_pMACKey[13], m_pMACKey[14], m_pMACKey[15]);

}

int GetKeyBundling(unsigned char *TMK, unsigned char *InitVec, unsigned char *EncKey, unsigned char *MACKey)
{
	memset(m_pTMK, 0x00, 16);
	memset(m_pRND, 0x00, 8);
	
	memcpy(m_pTMK, TMK, 16);
	memcpy(m_pRND, InitVec, 8);
	
	MakeSubKey();

	MakeEncryptKey();

	MakeMACKey();	
	
	memcpy(EncKey, m_pEncKey, 16);
	memcpy(MACKey, m_pMACKey, 16);
	
	return 0;
}

//m_pTDESKey : RND Data
int CheckBundlingKey()
{
	unsigned char InitVec[8] = {0x00,};
	int result;
	
	result = GetKeyBundling(m_pTDESKey, InitVec, m_pEncKey, m_pMACKey);
	
	return result;
}

// E(IPK + KSN) + MAC 형식의 데이터에서 뒤에 8바이트는 MAC 값입니다. E(IPK + KSN) 를 m_pMACKey로 암호화 하여 앞 8바이트를 사용합니다.
// E(IPK + KSN) 는 m_pEncKey 로 복호화 하면 데이터가 나옵니다.