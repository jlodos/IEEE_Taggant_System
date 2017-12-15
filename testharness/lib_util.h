/* ====================================================================
 * Copyright (c) 2015 IEEE.  All rights reserved.
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

#ifndef LIB_UTIL_HEADER
#define LIB_UTIL_HEADER

#include "taggant_types.h"

#define TAGGANT_MARKER_END 0x53544E41   /* 'A'N'T'S' */
#define TAGGANT_ADDRESS_JMP 0x08EB
#define TAGGANT_ADDRESS_JMP_SIZE 2

/* from types.h */
#define TAGGANT_VERSION1 1
#define TAGGANT_VERSION2 2
#define TAGGANT_VERSION3 3
#define TAGGANT_MARKER_BEGIN 0x47474154 /* 'T'A'G'G' */
#define TAGGANT_MARKER_END 0x53544E41   /* 'A'N'T'S' */

#pragma pack(push,2)

typedef struct
{
    UNSIGNED16 Length;
    /* not implemented in the current specification
    char Data[0]; */
} EXTRABLOB, *PEXTRABLOB;

typedef struct
{	
    UNSIGNED32 MarkerBegin;
    UNSIGNED32 TaggantLength;
    UNSIGNED32 CMSLength;
    UNSIGNED16 Version;
} TAGGANT_HEADER, *PTAGGANT_HEADER;

typedef struct
{	
    UNSIGNED16 Version;
    UNSIGNED32 CMSLength;
    UNSIGNED32 TaggantLength;
    UNSIGNED32 MarkerBegin;
} TAGGANT_HEADER2, *PTAGGANT_HEADER2;

typedef struct
{
    EXTRABLOB Extrablob;
    UNSIGNED32 MarkerEnd;
} TAGGANT_FOOTER, *PTAGGANT_FOOTER;

typedef struct
{
    UNSIGNED32 MarkerEnd;
} TAGGANT_FOOTER2, *PTAGGANT_FOOTER2;

typedef struct
{
    /* taggant offset from the beginning of the file */
    UNSIGNED64 offset;
    TAGGANT_HEADER Header;
    PVOID CMSBuffer;
    TAGGANT_FOOTER Footer;
} TAGGANT1, *PTAGGANT1;

typedef struct
{
    TAGGANT_HEADER2 Header;
    PVOID CMSBuffer;
    UNSIGNED32 CMSBufferSize;
    TAGGANT_FOOTER2 Footer;
    /* the current file position to check for a next taggant */
    UNSIGNED64 fileend;
    /* end of full file hash, the size of the file without taggants */
    UNSIGNED64 ffhend;
    /* type of the file currently processed */
    TAGGANTCONTAINER tagganttype;
} TAGGANT2, *PTAGGANT2;

#pragma pack(pop)

void taggant_free_taggant(PTAGGANT1 pTaggant);

void taggant2_free_taggant(PTAGGANT2 pTaggant);

UNSIGNED32 taggant_read_from_pe(const UNSIGNED8 *pefile, UNSIGNED64 pefile_len, PTAGGANT1 *pTaggant);

UNSIGNED32 taggant2_read_binary(const UNSIGNED8 *pefile, UNSIGNED64 offset, PTAGGANT2* pTaggant, TAGGANTCONTAINER filetype);

#endif
