#include <Windows.h>
#include <wmmintrin.h>
#include <stdio.h>


#include "Aes.intrinsic.h"


static void Aes256KeyExpansion(const unsigned char* pAesKey, __m128i* pKeySchedule)
{
    __m128i xmmTemp1, xmmTemp2, xmmTemp3;

    xmmTemp1 = _mm_loadu_si128((const __m128i*)pAesKey);
    xmmTemp2 = _mm_loadu_si128((const __m128i*)(pAesKey + 16));
    pKeySchedule[0] = xmmTemp1;
    pKeySchedule[1] = xmmTemp2;

    // Round 1
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x01);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[2] = xmmTemp1;

    // Round 1 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[3] = xmmTemp2;

    // Round 2
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x02);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[4] = xmmTemp1;

    // Round 2 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[5] = xmmTemp2;

    // Round 3
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x04);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[6] = xmmTemp1;

    // Round 3 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[7] = xmmTemp2;

    // Round 4
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x08);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[8] = xmmTemp1;

    // Round 4 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[9] = xmmTemp2;

    // Round 5
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x10);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[10] = xmmTemp1;

    // Round 5 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[11] = xmmTemp2;

    // Round 6
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x20);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[12] = xmmTemp1;

    // Round 6 (second half)
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp1, 0x00);
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_slli_si128(xmmTemp2, 4));
    xmmTemp2 = _mm_xor_si128(xmmTemp2, _mm_shuffle_epi32(xmmTemp3, 0xaa));
    pKeySchedule[13] = xmmTemp2;

    // Round 7
    xmmTemp3 = _mm_aeskeygenassist_si128(xmmTemp2, 0x40);
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_shuffle_epi32(xmmTemp3, 0xff));
    pKeySchedule[14] = xmmTemp1;
}





void Aes256Encrypt(IN const unsigned char* pPlainText, IN unsigned __int64 uPlainTextSize, IN unsigned char* pCipherText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbEncrypted)
{
    if (!pbEncrypted) return;
    
    *pbEncrypted = FALSE;

    if (!pPlainText || !pCipherText || !pAesKey || !pAesIv || uPlainTextSize == 0) return;
	if (uPlainTextSize % 16 != 0) return;

    __m128i xmmKeySchedule[15];
    Aes256KeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);

    for (int i = 0; i < uPlainTextSize; i += 16)
    {
        __m128i xmmBlock = _mm_loadu_si128((const __m128i*)(pPlainText + i));
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 14; iRound++)
        {
            xmmBlock = _mm_aesenc_si128(xmmBlock, xmmKeySchedule[iRound]);
        }

        xmmBlock = _mm_aesenclast_si128(xmmBlock, xmmKeySchedule[14]);
        _mm_storeu_si128((__m128i*)(pCipherText + i), xmmBlock);
        xmmChain = xmmBlock;
    }

	*pbEncrypted = TRUE;
}




void Aes256Decrypt(IN const unsigned char* pCipherText, IN unsigned __int64 uCipherTextSize, IN unsigned char* pPlainText, IN unsigned char* pAesKey, IN unsigned char* pAesIv, OUT PBOOLEAN pbDecrypted)
{

    if (!pbDecrypted) return;
    *pbDecrypted = FALSE;

	if (!pCipherText || !pPlainText || !pAesKey || !pAesIv || uCipherTextSize == 0) return;
	if (uCipherTextSize % 16 != 0) return;

    __m128i xmmEncKeySchedule[15];
    Aes256KeyExpansion(pAesKey, xmmEncKeySchedule);
	
    __m128i xmmDecKeySchedule[15];
    xmmDecKeySchedule[0] = xmmEncKeySchedule[14];
    for (int i = 1; i < 14; i++)
        xmmDecKeySchedule[i] = _mm_aesimc_si128(xmmEncKeySchedule[14 - i]);
    xmmDecKeySchedule[14] = xmmEncKeySchedule[0];

    __m128i xmmChain = _mm_loadu_si128((const __m128i*)pAesIv);

	
    for (int i = 0; i < uCipherTextSize; i += 16)
    {
        __m128i xmmCipherBlock = _mm_loadu_si128((const __m128i*)(pCipherText + i));
        __m128i xmmTemp = xmmCipherBlock;

        __m128i xmmBlock = _mm_xor_si128(xmmCipherBlock, xmmDecKeySchedule[0]);
        
        for (int iRound = 1; iRound < 14; iRound++)
            xmmBlock = _mm_aesdec_si128(xmmBlock, xmmDecKeySchedule[iRound]);
        
        xmmBlock = _mm_aesdeclast_si128(xmmBlock, xmmDecKeySchedule[14]);
        xmmBlock = _mm_xor_si128(xmmBlock, xmmChain);
        
        _mm_storeu_si128((__m128i*)(pPlainText + i), xmmBlock);

        xmmChain = xmmTemp;
    }
	
    *pbDecrypted = TRUE;
}



