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
 *
 * author: Peter Ferrie (peferrie@microsoft.com)
 */

#include <stddef.h>
#include <malloc.h>
#include <memory.h>
#include "lib_util.h"
#include "pe_util.h"

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

#if !defined(BIG_ENDIAN)
#define read_le16(offset) (*((UNSIGNED16 *) (offset)))
#define read_le32(offset) (*((UNSIGNED32 *) (offset)))
#define read_le64(offset) (*((UNSIGNED64 *) (offset)))
#else
#define read_le16(offset) (((unsigned int) *((PINFO) (offset) + 1) << 8) \
                         + *((PINFO) (offset) + 0) \
                          )
#define read_le32(offset) (((UNSIGNED32) *((PINFO) (offset) + 3) << 0x18) \
                         + ((UNSIGNED32) *((PINFO) (offset) + 2) << 0x10) \
                         + ((UNSIGNED32) *((PINFO) (offset) + 1) << 8) \
                         + *((PINFO) (offset) + 0) \
                          )
#define read_le64(offset) (((UNSIGNED64) *((PINFO) (offset) + 7) << 0x38) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 6) << 0x30) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 5) << 0x28) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 4) << 0x20) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 3) << 0x18) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 2) << 0x10) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 1) << 8) \
                         + *((PINFO) (offset) + 0) \
                          )
#endif

void taggant_free_taggant(PTAGGANT1 pTaggant)
{
    /* Make sure taggant object is not null */
    if (pTaggant)
    {
        if (pTaggant->CMSBuffer)
        {
            free(pTaggant->CMSBuffer);
        }
        free(pTaggant);
    }
}

void taggant2_free_taggant(PTAGGANT2 pTaggant)
{
    /* Make sure taggant object is not null */
    if (pTaggant)
    {
        if (pTaggant->CMSBuffer)
        {
            free(pTaggant->CMSBuffer);
        }
        free(pTaggant);
    }
}

UNSIGNED32 taggant_read_from_pe(const UNSIGNED8 *pefile, UNSIGNED64 pefile_len, PTAGGANT1 *pTaggant)
{
    UNSIGNED32 res = TNOTAGGANTS;
    UNSIGNED32 lfanew;
    unsigned int sectcount;
    TAG_IMAGE_SECTION_HEADER *secttbl;
    UNSIGNED32 epoffset;
    UNSIGNED16 jmpcode;
    UNSIGNED64 taggantoffset;
    PTAGGANT1 tagbuf = NULL;
    UNSIGNED32 tagsize;

    if (pefile_len < sizeof(TAG_IMAGE_DOS_HEADER))
    {
        return TINVALIDPEENTRYPOINT;
    }

    if ((read_le16(pefile) != IMAGE_DOS_SIGNATURE)
     || (pefile_len < ((lfanew = read_le32(pefile + offsetof(TAG_IMAGE_DOS_HEADER,
                                                             e_lfanew
                                                            )
                                          )
                       ) + offsetof(TAG_IMAGE_NT_HEADERS32,
                                    OptionalHeader
                                   )
                         + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                    BaseOfCode
                                   )
                      )
        )
     || (read_le32(pefile + lfanew) != IMAGE_NT_SIGNATURE)
       )
    {
        return TINVALIDPEENTRYPOINT;
    }

    epoffset = read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                      OptionalHeader
                                                     )
                                           + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                      AddressOfEntryPoint
                                                     )
                          );

    if ((sectcount = read_le16(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                          FileHeader
                                                         )
                                               + offsetof(TAG_IMAGE_FILE_HEADER,
                                                          NumberOfSections
                                                         )
                              )
        ) != 0
       )
    {
        unsigned int optsize;
        UNSIGNED64 imagesize;

        if (pefile_len < (lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                            OptionalHeader
                                           ) + (optsize = read_le16(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                                               FileHeader
                                                                                              )
                                                                                    + offsetof(TAG_IMAGE_FILE_HEADER,
                                                                                               SizeOfOptionalHeader
                                                                                              )
                                                                   )
                                               ) + (sectcount * sizeof(TAG_IMAGE_SECTION_HEADER))
                         )
           )
        {
            return TINVALIDPEENTRYPOINT;
        }

        if ((epoffset = virttophys(pefile_len,
                                     secttbl = (TAG_IMAGE_SECTION_HEADER *) (pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                                                        OptionalHeader
                                                                                                       ) + optsize
                                                                        ),
                                     sectcount,
                                     epoffset,
                                     read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                          OptionalHeader
                                                                         )
                                                               + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                                          FileAlignment
                                                                         )
                                              ),
                                     &imagesize
                                    )
            ) == -1
           )
        {
            return TINVALIDPEENTRYPOINT;
        }
    }

    /* read 2 bytes from file entry point */
    if (epoffset + sizeof(UNSIGNED16) + sizeof(UNSIGNED64) > pefile_len)
    {
        return TINVALIDPEENTRYPOINT;
    }
    memcpy(&jmpcode, pefile + epoffset, sizeof(UNSIGNED16));
#ifdef BIG_ENDIAN
    jmpcode = read_le16(&jmpcode);
#endif
    if (jmpcode != TAGGANT_ADDRESS_JMP)
    {
        return TINVALIDTAGGANTOFFSET;
    }
    memcpy(&taggantoffset, pefile + epoffset + sizeof(UNSIGNED16), sizeof(UNSIGNED64));
#ifdef BIG_ENDIAN
    taggant_offset = read_le64(&taggant_offset);
#endif

    /* seek from the file begin to the taggant */
    if (taggantoffset + sizeof(TAGGANT_HEADER) > pefile_len)
    {
        return TFILEACCESSDENIED;
    }
    /* allocate memory for taggant */
    tagbuf = malloc(sizeof(TAGGANT1));
    if (tagbuf)
    {
        memset(tagbuf, 0, sizeof(TAGGANT1));
        /* read taggant header */
        memcpy(&tagbuf->Header, pefile + taggantoffset, sizeof(TAGGANT_HEADER));
#ifdef BIG_ENDIAN
        tagbuf->Header.MarkerBegin = read_le32(&tagbuf->Header.MarkerBegin);
        tagbuf->Header.TaggantLength = read_le32(&tagbuf->Header.TaggantLength);
        tagbuf->Header.CMSLength = read_le32(&tagbuf->Header.CMSLength);
        tagbuf->Header.Version = read_le16(&tagbuf->Header.Version);
#endif
        if (tagbuf->Header.Version == TAGGANT_VERSION1 && tagbuf->Header.MarkerBegin == TAGGANT_MARKER_BEGIN && tagbuf->Header.TaggantLength >= TAGGANT_MINIMUM_SIZE && tagbuf->Header.TaggantLength <= TAGGANT_MAXIMUM_SIZE && tagbuf->Header.CMSLength && (tagbuf->Header.CMSLength <= (tagbuf->Header.TaggantLength - sizeof(TAGGANT_HEADER) - sizeof(TAGGANT_FOOTER))))
        {
            /* allocate buffer for CMS */
            tagsize = tagbuf->Header.TaggantLength - sizeof(TAGGANT_HEADER) - sizeof(TAGGANT_FOOTER);
            tagbuf->CMSBuffer = malloc(tagsize);
            if (tagbuf->CMSBuffer)
            {
                memset(tagbuf->CMSBuffer, 0, tagsize);
				if (taggantoffset + tagbuf->Header.TaggantLength <= pefile_len)
                {
                    /* read CMS */
                    memcpy(tagbuf->CMSBuffer, pefile + taggantoffset + sizeof(TAGGANT_HEADER), tagsize);
                    /* read taggant footer */
                    memcpy(&tagbuf->Footer, pefile + taggantoffset + sizeof(TAGGANT_HEADER) + tagsize, sizeof(TAGGANT_FOOTER));
#ifdef BIG_ENDIAN
                    tagbuf->Footer.Extrablob.Length = read_le16(&tagbuf->Footer.Extrablob.Length);
                    tagbuf->Footer.MarkerEnd = read_le32(&tagbuf->Footer.MarkerEnd);
#endif
                    if (tagbuf->Footer.MarkerEnd == TAGGANT_MARKER_END)
                    {
                        tagbuf->offset = taggantoffset;
                        *pTaggant = tagbuf;
                        res = TNOERR;
                    }
                    else
                    {
                        res = TNOTAGGANTS;
                    }
                }
                else
                {
                    res = TFILEACCESSDENIED;
                }
            }
            else
            {
                res = TMEMORY;
            }
        }
        else
        {
            res = TNOTAGGANTS;
        }
        if (res != TNOERR) 
        {
            taggant_free_taggant(tagbuf);
        }
    }
    else
    {
        res = TMEMORY;
    }

    return res;
}

UNSIGNED32 taggant2_read_binary(const UNSIGNED8 *pefile, UNSIGNED64 offset, PTAGGANT2* pTaggant, TAGGANTCONTAINER filetype)
{
    UNSIGNED32 res = TNOTAGGANTS;
    PTAGGANT2 tagbuf = NULL;
    UNSIGNED16 hdver = (filetype == TAGGANT_PESEALFILE) ? TAGGANT_VERSION3 : TAGGANT_VERSION2;

    /* seek to the specified offset */
	if (offset > sizeof(TAGGANT_HEADER2))
    {
        offset -= sizeof(TAGGANT_HEADER2);
        /* allocate memory for taggant */
        tagbuf = (PTAGGANT2)malloc(sizeof(TAGGANT2));
        if (tagbuf)
        {
            memset(tagbuf, 0, sizeof(TAGGANT2));
            /* remember the taggant type */
            tagbuf->tagganttype = filetype;
            /* read taggant header */
            memcpy(&tagbuf->Header, pefile + offset, sizeof(TAGGANT_HEADER2));
#ifdef BIG_ENDIAN
			tagbuf->Header.Version = read_le16(&tagbuf->Header.Version);
			tagbuf->Header.CMSLength = read_le32(&tagbuf->Header.CMSLength);
			tagbuf->Header.TaggantLength = read_le32(&tagbuf->Header.TaggantLength);
			tagbuf->Header.MarkerBegin = read_le32(&tagbuf->Header.MarkerBegin);
#endif
            if (tagbuf->Header.Version == hdver && tagbuf->Header.MarkerBegin == TAGGANT_MARKER_BEGIN && tagbuf->Header.CMSLength)
            {
                /* allocate buffer for CMS */				
                tagbuf->CMSBuffer = malloc(tagbuf->Header.CMSLength);
                if (tagbuf->CMSBuffer)
                {
                    memset(tagbuf->CMSBuffer, 0, tagbuf->Header.CMSLength);
                    tagbuf->CMSBufferSize = tagbuf->Header.CMSLength;
                    if (offset > tagbuf->Header.CMSLength)
                    {
                        /* seek to the CMS offset */
                        offset -= tagbuf->Header.CMSLength;
                        /* read CMS */
                        memcpy(tagbuf->CMSBuffer, pefile + offset, tagbuf->Header.CMSLength);
						if (offset > sizeof(UNSIGNED32))
                        {
                            offset -= sizeof(UNSIGNED32);
                            /* read end marker */
                            tagbuf->Footer.MarkerEnd = read_le32(pefile + offset);
                            /* check end marker */
                            if (tagbuf->Footer.MarkerEnd == TAGGANT_MARKER_END)
                            {
                                /* make sure there is no appended data in cms */
                                if (tagbuf->Header.TaggantLength == sizeof(TAGGANT_HEADER2) + tagbuf->Header.CMSLength + /* TAGGANT_FOOTER2 length */ sizeof(UNSIGNED32))
                                {
                                    *pTaggant = tagbuf;
                                    res = TNOERR;
                                }
                            }
                        }
                        else
                        {
                            res = TFILEACCESSDENIED;
                        }
                    }
                    else
                    {
                        res = TFILEACCESSDENIED;
                    }
                }
                else
                {
                    res = TMEMORY;
                }
            }
            if (res != TNOERR) 
            {
                taggant2_free_taggant(tagbuf);
            }
        }
        else
        {
            res = TMEMORY;
        }
    }
    else
    {
        res = TFILEACCESSDENIED;
    }
    return res;
}

