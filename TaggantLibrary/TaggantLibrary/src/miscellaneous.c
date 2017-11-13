/* ====================================================================
 * Copyright (c) 2012 IEEE.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the IEEE Industry
 *    Connections Security Group (ICSG)".
 *
 * 4. The name "IEEE" must not be used to endorse or promote products
 *    derived from this software without prior written permission from
 *    the IEEE Standards Association (stds.ipr@ieee.org).
 *
 * 5. Products derived from this software may not contain "IEEE" in
 *    their names without prior written permission from the IEEE Standards
 *    Association (stds.ipr@ieee.org).
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the IEEE Industry
 *    Connections Security Group (ICSG)".
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND "WITH ALL FAULTS." IEEE AND ITS
 * CONTRIBUTORS EXPRESSLY DISCLAIM ALL WARRANTIES AND REPRESENTATIONS,
 * EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION:  (A) THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE;
 * (B) ANY WARRANTY OF NON-INFRINGEMENT; AND (C) ANY WARRANTY WITH RESPECT
 * TO THE QUALITY, ACCURACY, EFFECTIVENESS, CURRENCY OR COMPLETENESS OF
 * THE SOFTWARE.
 *
 * IN NO EVENT SHALL IEEE OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR CONSEQUENTIAL DAMAGES,
 * (INCLUDING, BUT NOT LIMITED TO,  PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE AND REGARDLESS OF WHETHER SUCH DAMAGE WAS
 * FORESEEABLE.
 *
 * THIS SOFTWARE USES STRONG CRYPTOGRAPHY, WHICH MAY BE SUBJECT TO LAWS
 * AND REGULATIONS GOVERNING ITS USE, EXPORTATION OR IMPORTATION. YOU ARE
 * SOLELY RESPONSIBLE FOR COMPLYING WITH ALL APPLICABLE LAWS AND
 * REGULATIONS, INCLUDING, BUT NOT LIMITED TO, ANY THAT GOVERN YOUR USE,
 * EXPORTATION OR IMPORTATION OF THIS SOFTWARE. IEEE AND ITS CONTRIBUTORS
 * DISCLAIM ALL LIABILITY ARISING FROM YOUR USE OF THE SOFTWARE IN
 * VIOLATION OF ANY APPLICABLE LAWS OR REGULATIONS.
 * ====================================================================
 */

#include "global.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "callbacks.h"
#include "taggantlib.h"
#include "endianness.h"

unsigned long round_up(unsigned long alignment, unsigned long size)
{
    return (size + alignment - 1) & (0 - alignment);
}

unsigned long round_down(unsigned long alignment, unsigned long size)
{
    return size & (0 - alignment);
}

unsigned long get_min(unsigned long v1, unsigned long v2)
{
    return (v1 < v2) ? v1 : v2;
}

unsigned long get_max(unsigned long v1, unsigned long v2)
{
    return (v1 > v2) ? v1 : v2;
}

UNSIGNED64 get_file_size (PTAGGANTCONTEXT pCtx, PFILEOBJECT fp)
{
    UNSIGNED64 size;
    UNSIGNED64 pos = pCtx->FileTellCallBack(fp);
    pCtx->FileSeekCallBack(fp, 0, SEEK_END);
    size = pCtx->FileTellCallBack(fp);
    pCtx->FileSeekCallBack(fp, pos, SEEK_SET);
    return size;
}

int file_seek(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, int type)
{
    return pCtx->FileSeekCallBack(fp, offset, type) == 0 ? 1 : 0;
}

int file_read_buffer(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, void* buffer, size_t length)
{
    return (pCtx->FileReadCallBack(fp, buffer, length) == length) ? 1 : 0;
}

int file_read_UNSIGNED16(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED16 *value)
{
    if (pCtx->FileReadCallBack(fp, value, sizeof(UNSIGNED16)) == sizeof(UNSIGNED16))
    {
        if (IS_BIG_ENDIAN)
        {
            *value = UNSIGNED16_to_big_endian((char*)value);
        }
        return 1;
    }
    return 0;
}

int file_read_UNSIGNED32(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED32 *value)
{
    if (pCtx->FileReadCallBack(fp, value, sizeof(UNSIGNED32)) == sizeof(UNSIGNED32))
    {
        if (IS_BIG_ENDIAN)
        {
            *value = UNSIGNED32_to_big_endian((char*)value);
        }
        return 1;
    }
    return 0;
}

int file_read_UNSIGNED64(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 *value)
{
    if (pCtx->FileReadCallBack(fp, value, sizeof(UNSIGNED64)) == sizeof(UNSIGNED64))
    {
        if (IS_BIG_ENDIAN)
        {
            *value = UNSIGNED64_to_big_endian((char*)value);
        }
        return 1;
    }
    return 0;
}

int file_read_textual_UNSIGNED16(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED16 *value)
{
    char buf[5];

    memset(&buf, 0, sizeof(buf));
    if (pCtx->FileReadCallBack(fp, &buf, sizeof(buf) - 1) == sizeof(buf) - 1)
    {
        *value = (UNSIGNED16)strtol((char*)&buf, NULL, 16);
        return 1;
    }
    return 0;
}

int file_read_textual_UNSIGNED32(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED32 *value)
{
    char buf[9];

    memset(&buf, 0, sizeof(buf));
    if (pCtx->FileReadCallBack(fp, &buf, sizeof(buf) - 1) == sizeof(buf) - 1)
    {
        *value = (UNSIGNED32)strtol((char*)&buf, NULL, 16);
        return 1;
    }
    return 0;
}

int file_read_textual_buffer(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PVOID buffer, UNSIGNED16 length)
{
    PVOID tmpbuf;
    int i, res = 0, len;
    char buf[3], *intmpbuf, *outtmpbuf;
    
    len = length * 2;
    tmpbuf = memory_alloc(len);
    if (tmpbuf)
    {
        memset(tmpbuf, 0, len);
        if ((int)pCtx->FileReadCallBack(fp, tmpbuf, len) == len)
        {
            memset(buf, 0, sizeof(buf));
            intmpbuf = (char*)tmpbuf;
            outtmpbuf = (char*)buffer;
            for (i = 0; i < len; i += 2)
            {
                buf[0] = *intmpbuf;
                intmpbuf++;
                buf[1] = *intmpbuf;
                intmpbuf++;
                *outtmpbuf = (UNSIGNED8)strtol((char*)&buf, NULL, 16);
                outtmpbuf++;
            }
            res = 1;
        }
        memory_free(tmpbuf);
    }
    return res;
}

/********************************************************************************************/
/* Modified from ConvertUTF.h and ConvertUTF.c from Unicode, Inc. */

/*
* Copyright 2001-2004 Unicode, Inc.
*
* Disclaimer
*
* This source code is provided as is by Unicode, Inc. No claims are
* made as to fitness for any particular purpose. No warranties of any
* kind are expressed or implied. The recipient agrees to determine
* applicability of information provided. If this file has been
* purchased on magnetic or optical media from Unicode, Inc., the
* sole remedy for any claim will be exchange of defective media
* within 90 days of receipt.
*
* Limitations on Rights to Redistribute This Code
*
* Unicode, Inc. hereby grants the right to freely use the information
* supplied in this file in the creation of products supporting the
* Unicode Standard, and to make copies of this file in any form
* for internal or external distribution as long as this notice
* remains attached.
*/

/* Some fundamental constants */
#define UNI_REPLACEMENT_CHAR (UNSIGNED32)0x0000FFFD

static int halfShift = 10; /* used for shifting by 10 bits */

static UNSIGNED32 halfBase = 0x0010000UL;
static UNSIGNED32 halfMask = 0x3FFUL;

#define UNI_SUR_HIGH_START  (UNSIGNED32)0xD800
#define UNI_SUR_HIGH_END    (UNSIGNED32)0xDBFF
#define UNI_SUR_LOW_START   (UNSIGNED32)0xDC00
#define UNI_SUR_LOW_END     (UNSIGNED32)0xDFFF

/*
* Once the bits are split out into bytes of UTF-8, this is a mask OR-ed
* into the first byte, depending on how many bytes follow.  There are
* as many entries in this table as there are UTF-8 sequence types.
* (I.e., one byte sequence, two byte... etc.). Remember that sequencs
* for *legal* UTF-8 will be 4 or fewer bytes total.
*/
static UNSIGNED8 firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };

typedef enum {
    conversionOK, 		/* conversion successful */
    sourceExhausted,	/* partial character in source, but hit end */
    targetExhausted,	/* insuff. room in target for conversion */
    sourceIllegal		/* source sequence is illegal/malformed */
} ConversionResult;

typedef enum {
    strictConversion = 0,
    lenientConversion
} ConversionFlags;

ConversionResult ConvertUTF16toUTF8(UNSIGNED16** sourceStart, UNSIGNED16* sourceEnd, UNSIGNED8** targetStart, UNSIGNED8* targetEnd, ConversionFlags flags)
{
    ConversionResult result = conversionOK;
    UNSIGNED32 byteMask = 0xBF;
    UNSIGNED32 byteMark = 0x80;
    UNSIGNED16* source = *sourceStart;
    UNSIGNED8* target = *targetStart;
    UNSIGNED16* oldSource = source; /* In case we have to back up because of target overflow. */
    UNSIGNED32 ch;
    unsigned short bytesToWrite;
    while (source < sourceEnd)
    {
        ch = *source++;
        /* If we have a surrogate pair, convert to UTF32 first. */
        if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
            /* If the 16 bits following the high surrogate are in the source buffer... */
            if (source < sourceEnd) {
                UNSIGNED32 ch2 = *source;
                /* If it's a low surrogate, convert to UTF32. */
                if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
                    ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
                        + (ch2 - UNI_SUR_LOW_START) + halfBase;
                    ++source;
                }
                else if (flags == strictConversion) { /* it's an unpaired high surrogate */
                    --source; /* return to the illegal value itself */
                    result = sourceIllegal;
                    break;
                }
            }
            else { /* We don't have the 16 bits following the high surrogate. */
                --source; /* return to the high surrogate */
                result = sourceExhausted;
                break;
            }
        }
        else if (flags == strictConversion) {
            /* UTF-16 surrogate values are illegal in UTF-32 */
            if (ch >= UNI_SUR_LOW_START && ch <= UNI_SUR_LOW_END) {
                --source; /* return to the illegal value itself */
                result = sourceIllegal;
                break;
            }
        }
        /* Figure out how many bytes the result will require */
        if (ch < (UNSIGNED32)0x80) {
            bytesToWrite = 1;
        }
        else if (ch < (UNSIGNED32)0x800) {
            bytesToWrite = 2;
        }
        else if (ch < (UNSIGNED32)0x10000) {
            bytesToWrite = 3;
        }
        else if (ch < (UNSIGNED32)0x110000) {
            bytesToWrite = 4;
        }
        else {
            bytesToWrite = 3;
            ch = UNI_REPLACEMENT_CHAR;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            source = oldSource; /* Back up source pointer! */
            target -= bytesToWrite;
            result = targetExhausted;
            break;
        }
        switch (bytesToWrite) { /* note: everything falls through. */
        case 4: *--target = (UNSIGNED8)((ch | byteMark) & byteMask); ch >>= 6;
        case 3: *--target = (UNSIGNED8)((ch | byteMark) & byteMask); ch >>= 6;
        case 2: *--target = (UNSIGNED8)((ch | byteMark) & byteMask); ch >>= 6;
        case 1: *--target = (UNSIGNED8)(ch | firstByteMark[bytesToWrite]);
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

/* Modified from ConvertUTF.h and ConvertUTF.c from Unicode, Inc. */
/********************************************************************************************/

int convert_utf16_to_utf8(UNSIGNED16** sourceStart, UNSIGNED8** targetStart, UNSIGNED8* targetEnd)
{
    UNSIGNED16* sourceEnd = *sourceStart;
    while (*sourceEnd)
        sourceEnd++;
    sourceEnd++; /* include NULL terminator */
    return conversionOK == ConvertUTF16toUTF8(sourceStart, sourceEnd, targetStart, targetEnd, strictConversion);
}
