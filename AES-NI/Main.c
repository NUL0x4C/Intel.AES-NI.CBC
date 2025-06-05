#include <Windows.h>
#include <stdio.h>



#include "Aes.intrinsic.h"



static const unsigned char	g_PlainText[]	=	"\tThis is a test of AES encryption using AES-NI intrinsics.\n"
							"\tThe (V)PSRLW instruction shifts each of the words in the destination operand to the right by the number of bits.\n"
							"\tspecified in the count operand; the(V)PSRLD instruction shifts each of the doublewords in the destination operand.\n"
							"\tand the PSRLQ instruction shifts the quadword(or quadwords) in the destination operand.\n"
							"\tVol. 2B 4-459\n";

static unsigned char		g_AesKey[]		= {
	0x01, 0x57, 0xBB, 0xC8, 0x8F, 0x49, 0x1E, 0x6A, 0x6A, 0xA5, 0xF9, 0x8C, 0x11, 0x40, 0x19, 0x2D,
	0x72, 0x38, 0x40, 0x35, 0xEE, 0xFA, 0x21, 0xCA, 0x92, 0x85, 0x4D, 0xA1, 0x25, 0xF1, 0x5C, 0x2E
};

static unsigned char		g_AesIv[]		= {
	0x3C, 0xB1, 0xE0, 0x1E, 0x70, 0x2B, 0x0C, 0xCE, 0x24, 0xB2, 0x89, 0x70, 0xF2, 0x2B, 0x43, 0x99
};




int main() { 


	unsigned char*		pCipherText		= NULL;
	unsigned char*		pPaddedPlainText	= NULL;
	unsigned char*		pPlainText		= NULL;
	unsigned __int64	uPlainTextSize		= (strlen((char*)g_PlainText) + 15) & ~(size_t)0x0F;			// multiple of 16
	unsigned char 		bEncrypted		= FALSE;
	unsigned char 		bDecrypted		= FALSE;


	if (!(pPaddedPlainText = (unsigned char*)malloc(uPlainTextSize)))
	{
		return -1;
	}
	
	if (!(pCipherText = (unsigned char*)malloc(uPlainTextSize))) 
	{
		free(pPaddedPlainText);
		return -1;
	}


	if (!(pPlainText = (unsigned char*)malloc(uPlainTextSize)))
	{
		free(pPaddedPlainText);
		free(pCipherText);
		return -1;
	}

	memset(pPaddedPlainText, 0x00, uPlainTextSize);
	memcpy(pPaddedPlainText, g_PlainText, strlen((char*)g_PlainText));

	Aes256Encrypt(pPaddedPlainText, uPlainTextSize, pCipherText, g_AesKey, g_AesIv, &bEncrypted);

	if (!bEncrypted)
	{
		free(pPaddedPlainText);
		free(pCipherText);
		free(pPlainText);
		return -1;
	}

	printf("[*] Encryption Was Successful!\n");

	Aes256Decrypt(pCipherText, uPlainTextSize, pPlainText, g_AesKey, g_AesIv, &bDecrypted);

	if (!bDecrypted)
	{
		free(pPaddedPlainText);
		free(pCipherText);
		free(pPlainText);
		return -1;
	}

	printf("[*] Decryption Was Successful!\n");
	printf("[*] Decrypted Text: \n%s\n", pPlainText);


	free(pPaddedPlainText);
	free(pCipherText);
	free(pPlainText);

	return 0;
}





