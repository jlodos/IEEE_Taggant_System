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
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "pe_util.h"
#include "file_util.h"
#include "lib_util.h"
#include "err.h"

#if !defined(BIG_ENDIAN)
#define read_le16(offset) (*((UNSIGNED16 *) (offset)))
#define read_le32(offset) (*((UNSIGNED32 *) (offset)))
#define read_le64(offset) (*((UNSIGNED64 *) (offset)))
#define write_le16(offset, value) (*((UNSIGNED16 *) (offset)) = (UNSIGNED16)(value))
#define write_le32(offset, value) (*((UNSIGNED32 *) (offset)) = (UNSIGNED32)(value))
#define write_le64(offset, value) (*((UNSIGNED64 *) (offset)) = (UNSIGNED64)(value))
#else
#define read_le16(offset) (((unsigned int) *((PINFO) (offset) + 1) << 8) \
                         + *((PINFO) (offset) + 0) \
                          )
#define read_le32(offset) (((UNSIGNED32) *((PINFO) (offset) + 3) << 0x18) \
                         + ((UNSIGNED32) *((PINFO) (offset) + 2) << 0x10) \
                         + ((UNSIGNED32) *((PINFO) (offset) + 1) << 0x08) \
                         + *((PINFO) (offset) + 0) \
                          )
#define read_le64(offset) (((UNSIGNED64) *((PINFO) (offset) + 7) << 0x38) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 6) << 0x30) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 5) << 0x28) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 4) << 0x20) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 3) << 0x18) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 2) << 0x10) \
                         + ((UNSIGNED64) *((PINFO) (offset) + 1) << 0x08) \
                         + *((PINFO) (offset) + 0) \
                          )
#define write_le16(offset, value) (*((UINT16 *) (offset)) = (((UNSIGNED16)(value) & 0x00ff) << 8) \
                                                          + (((UNSIGNED16)(value) & 0xff00) >> 8) \
                                  )
#define write_le32(offset, value) (*((UINT32 *) (offset)) = (((UNSIGNED32)(value) & 0x000000ff) << 24) \
                                                          + (((UNSIGNED32)(value) & 0x0000ff00) << 8)  \
                                                          + (((UNSIGNED32)(value) & 0x00ff0000) >> 8)  \
                                                          + (((UNSIGNED32)(value) & 0xff000000) >> 24) \
                                  )
#define write_le64(offset, value) (*((UINT64 *) (offset)) = (((UNSIGNED64)(value) & 0x00000000000000fful) << 56) \
                                                          + (((UNSIGNED64)(value) & 0x000000000000ff00ul) << 40) \
                                                          + (((UNSIGNED64)(value) & 0x0000000000ff0000ul) << 24) \
                                                          + (((UNSIGNED64)(value) & 0x00000000ff000000ul) << 8)  \
                                                          + (((UNSIGNED64)(value) & 0x000000ff00000000ul) >> 8)  \
                                                          + (((UNSIGNED64)(value) & 0x0000ff0000000000ul) << 24) \
                                                          + (((UNSIGNED64)(value) & 0x00ff000000000000ul) >> 40) \
                                                          + (((UNSIGNED64)(value) & 0xff00000000000000ul) >> 56) \
                                  )
#endif

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

#define IMAGE_FILE_MACHINE_I386		0x014c /* Intel 386 or later processors */
#define IMAGE_FILE_MACHINE_AMD64	0x8664 /* x64 */

#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory

void fix_image_size(const UNSIGNED8 *pefile, UNSIGNED64 pefile_len,
                    UNSIGNED64 imagesize,
                    _Out_writes_(1) UNSIGNED64 *fixedimagesize
                   )
{
    UNSIGNED64 fileend_without_taggants, fileend_without_signature;
    UNSIGNED32 ds_offset = 0, ds_size = 0;
    PTAGGANT1 taggant1 = NULL;
    PTAGGANT2 taggant2 = NULL;

    fileend_without_signature = pefile_len;
    unsigned int lfanew = read_le32(pefile + offsetof(TAG_IMAGE_DOS_HEADER, e_lfanew));
    unsigned int optsize = read_le16(pefile + lfanew
                                            + offsetof(TAG_IMAGE_NT_HEADERS32, FileHeader)
                                            + offsetof(TAG_IMAGE_FILE_HEADER, SizeOfOptionalHeader));
    unsigned int machine = read_le16(pefile + lfanew
                                            + offsetof(TAG_IMAGE_NT_HEADERS32, FileHeader)
                                            + offsetof(TAG_IMAGE_FILE_HEADER, Machine));
    if (machine == IMAGE_FILE_MACHINE_AMD64)
    {
        unsigned int dd_sec_pos = lfanew + offsetof(TAG_IMAGE_NT_HEADERS64, OptionalHeader)
                                            + offsetof(TAG_IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                            + IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(TAG_IMAGE_DATA_DIRECTORY);
        if (lfanew + offsetof(TAG_IMAGE_NT_HEADERS64, OptionalHeader) + optsize >= dd_sec_pos + sizeof(TAG_IMAGE_DATA_DIRECTORY))
        {
            ds_offset = read_le32(pefile + dd_sec_pos);
            ds_size = read_le32(pefile + dd_sec_pos + 4);
        }
    }
    else
    {
        unsigned int dd_sec_pos = lfanew + offsetof(TAG_IMAGE_NT_HEADERS32, OptionalHeader)
                                            + offsetof(TAG_IMAGE_OPTIONAL_HEADER32, DataDirectory)
                                            + IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(TAG_IMAGE_DATA_DIRECTORY);
        if (lfanew + offsetof(TAG_IMAGE_NT_HEADERS32, OptionalHeader) + optsize >= dd_sec_pos + sizeof(TAG_IMAGE_DATA_DIRECTORY))
        {
            ds_offset = read_le32(pefile + dd_sec_pos);
            ds_size = read_le32(pefile + dd_sec_pos + 4);
        }
    }
    if (ds_offset != 0 && ds_size != 0 && (ds_offset + ds_size) == pefile_len)
    {
        fileend_without_signature -= ds_size;
        /* check padding to 8 byte boundary as per PE/COFF specification */
        for (int i = 6; i >= 0 && !pefile[fileend_without_signature - 1]; i--)
        {
            /* exclude 0s to align assuming there is a taggant */
            fileend_without_signature--;
        }
    }

    fileend_without_taggants = fileend_without_signature;
	while (taggant2_read_binary(pefile, fileend_without_taggants, &taggant2, TAGGANT_PEFILE) == TNOERR)
    {
        fileend_without_taggants -= taggant2->Header.TaggantLength;
        taggant2_free_taggant(taggant2);
    }

    if (taggant_read_from_pe(pefile, pefile_len, &taggant1) == TNOERR)
    {
        if (fileend_without_taggants == taggant1->offset + taggant1->Header.TaggantLength)
        {
            /* the v1 taggant was at the end of the file */
            if (fileend_without_taggants > imagesize && taggant1->offset < imagesize)
            {
                /* the v1 taggant is outside the sections, but started withim them */
                fileend_without_taggants -= taggant1->Header.TaggantLength;
            }
        }
        taggant_free_taggant(taggant1);
    }

    *fixedimagesize = imagesize;
    if (imagesize > fileend_without_taggants)
    {
        /* could happen if last section alignment causes padding in memory */
        *fixedimagesize = fileend_without_taggants;
    }
}

UNSIGNED32 virttophys(UNSIGNED64 pefile_len,
                      _In_reads_(sectcount) const TAG_IMAGE_SECTION_HEADER *secttbl,
                      unsigned int sectcount,
                      UNSIGNED32 virtoff,
                      UNSIGNED32 filealign,
                      _Out_writes_(1) UNSIGNED64 *imagesize
                     )
{
    if (sectcount)
    {
        UNSIGNED32 invalid = 0xffffffff;
        UNSIGNED32 physoff = virtoff;
        UNSIGNED32 maxsize = 0;
        unsigned int hdrchk = 0;

        do
        {
            UNSIGNED32 rawptr;
            UNSIGNED32 rawalign;
            UNSIGNED32 rawsize;
            UNSIGNED32 readsize;
            UNSIGNED32 virtsize;
            UNSIGNED32 virtaddr = 0; /* keep compiler happy */

            rawalign = (rawptr = read_le32(&secttbl->PointerToRawData)) & ~0x1ff;
            readsize = ((rawptr + (rawsize = read_le32(&secttbl->SizeOfRawData)) + filealign - 1) & ~(filealign - 1)) - rawalign;
            readsize = min(readsize, (rawsize + 0xfff) & ~0xfff);

            if ((virtsize = read_le32(&secttbl->Misc.VirtualSize)) != 0)
            {
                readsize = min(readsize,
                               (virtsize + 0xfff) & ~0xfff
                              );
            }

            if (invalid
             && ((virtaddr = read_le32(&secttbl->VirtualAddress)) <= virtoff)
             && ((virtaddr + readsize) > virtoff)
               )
            {
                physoff = rawalign + virtoff - virtaddr;
                ++invalid;
            }

            if (!hdrchk)
            {
                /* if entrypoint is in header */

                if (invalid)
                {
                    invalid += (virtoff < virtaddr);
                }

                ++hdrchk;
            }

            if (rawptr
             && readsize
             && ((rawalign + readsize) > maxsize)
               )
            {
                maxsize = rawalign + readsize;
            }

            ++secttbl;
        }
        while (--sectcount);

        *imagesize = maxsize;
        return (physoff | invalid);
    }

    *imagesize = pefile_len;
    return virtoff;
}

int object_sizes(_In_reads_(pefile_len) const UNSIGNED8 *pefile,
                 UNSIGNED64 pefile_len,
                 UNSIGNED64 *ppeobj_len,
                 UNSIGNED64 *ppefixedobj_len,
                 UNSIGNED64 *ptag_off,
                 UNSIGNED32 *ptag_len
                )
{
    UNSIGNED32 lfanew;
    UNSIGNED32 entrypoint;
    unsigned int sectcount;
    TAG_IMAGE_SECTION_HEADER *secttbl;
    UNSIGNED64 tag_off;
    const UNSIGNED8 *tmp_ptr;
    const UNSIGNED8 *tag_ptr = 0; /* keep compiler happy */
    UNSIGNED32 tag_len;

    if (pefile_len < sizeof(TAG_IMAGE_DOS_HEADER))
    {
        return ERR_BADPE;
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
        return ERR_BADPE;
    }

    *ppeobj_len = pefile_len;
    entrypoint = read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
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
            return ERR_BADPE;
        }

        if ((entrypoint = virttophys(pefile_len,
                                     secttbl = (TAG_IMAGE_SECTION_HEADER *) (pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                                                    OptionalHeader
                                                                                                   ) + optsize
                                                                        ),
                                     sectcount,
                                     entrypoint,
                                     read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                          OptionalHeader
                                                                         )
                                                               + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                                          FileAlignment
                                                                         )
                                              ),
                                     ppeobj_len
                                    )
            ) == -1
           )
        {
            return ERR_BADPE;
        }
        fix_image_size(pefile, pefile_len, *ppeobj_len, ppefixedobj_len);
    }

    tag_off = read_le64(pefile + entrypoint + TAGGANT_ADDRESS_JMP_SIZE);
    if (ptag_off)
    {
        *ptag_off = tag_off;
    }
    if ((pefile_len < (entrypoint + TAGGANT_ADDRESS_JMP_SIZE + 8))
     || (read_le16(pefile + entrypoint) != TAGGANT_ADDRESS_JMP)
     || (pefile_len < tag_off)
     || ((pefile_len != tag_off)
      && (pefile_len < (tag_off + sizeof(TAGGANT_MARKER_END)))
        )
       )
    {
        return TNOTAGGANTS;
    }

    if (ptag_len)
    {
        *ptag_len = 0;
    }

    if (pefile_len != tag_off)
    {
        tmp_ptr = pefile + tag_off;
        tag_len = (UNSIGNED32) ((pefile_len - tag_off) - (sizeof(TAGGANT_MARKER_END) - 1));

        while (tag_len
            && ((tag_ptr = (const UNSIGNED8 *) memchr(tmp_ptr,
                                                      TAGGANT_MARKER_END & 0xff,
                                                      tag_len
                                                     )
                ) != NULL
               )
            && (read_le32(tag_ptr) != TAGGANT_MARKER_END)
              )
        {
            tag_len -= tag_ptr + 1 - tmp_ptr;
            tmp_ptr = tag_ptr + 1;
        }

        if (!tag_len
         || !tag_ptr
           )
        {
            return TNOTAGGANTS;
        }

        if (ptag_len)
        {
            *ptag_len = (UNSIGNED32) (tag_ptr + sizeof(TAGGANT_MARKER_END) - (pefile + tag_off));
        }
    }

    return ERR_NONE;
}

int add_section(_In_z_ const char *filename, 
                _In_z_ const char *sectionname,
                _In_z_ const UNSIGNED8 *sectioncontent,
                UNSIGNED32 sectionsize,
                UNSIGNED32 sectioncharacteristics
               )
{
    UNSIGNED8 *pefile;
    UNSIGNED64 pefile_len;
    UNSIGNED32 lfanew, filealignment, sectionalignment, sizeofheaders;
    unsigned int sectcount;
    TAG_IMAGE_SECTION_HEADER *secttbl;
    unsigned int optsize;
    UNSIGNED64 new_section_offset;
    UNSIGNED8 *tmpbuff;

    if ((read_tmp_file(filename,
                       &pefile,
                       &pefile_len
                      )
        ) != ERR_NONE
       )
    {
        return TFILEACCESSDENIED;
    }

    if (pefile_len < sizeof(TAG_IMAGE_DOS_HEADER))
    {
        free(pefile);
        return TINVALIDPEFILE;
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
        free(pefile);
        return TINVALIDPEFILE;
    }

    if ((sectcount = read_le16(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                          FileHeader
                                                         )
                                               + offsetof(TAG_IMAGE_FILE_HEADER,
                                                          NumberOfSections
                                                         )
                              )
        ) == 0
       )
    {
        free(pefile);
        return TINVALIDPEFILE;
    }

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
        free(pefile);
        return TINVALIDPEFILE;
    }

    filealignment = read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                         OptionalHeader
                                                        )
                                              + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                         FileAlignment
                                                        )
                             );
    sectionalignment = read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                            OptionalHeader
                                                           )
                                                 + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                            SectionAlignment
                                                           )
                                );
    sizeofheaders = read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                         OptionalHeader
                                                        )
                                              + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                         SizeOfHeaders
                                                        )
                             );
    secttbl = (TAG_IMAGE_SECTION_HEADER *) (pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                       OptionalHeader
                                                                      ) + optsize
                                       );

    /* Add the section at the end with alignment */
    new_section_offset = pefile_len;
	if (new_section_offset % filealignment)
    {
        new_section_offset += filealignment - (new_section_offset % filealignment);
    }

    /* Check if there is space in the headers for the new section entry */
    if (lfanew + 4 + sizeof(TAG_IMAGE_FILE_HEADER) + optsize + (sectcount+1)*sizeof(TAG_IMAGE_SECTION_HEADER) > sizeofheaders)
    {
        free(pefile);
        return TENTRIESEXCEED; /* instead of moving all sections down to free space after the headers */
    }

    /* add the new entry in the section table */
    memset(&secttbl[sectcount], 0, sizeof(TAG_IMAGE_SECTION_HEADER));
    strncpy((char*)secttbl[sectcount].Name, sectionname, 8); 
    secttbl[sectcount].Misc.VirtualSize = sectionsize;
    if (secttbl[sectcount].Misc.VirtualSize % sectionalignment)
    {
        secttbl[sectcount].Misc.VirtualSize += sectionalignment - (secttbl[sectcount].Misc.VirtualSize % sectionalignment);
    }
    secttbl[sectcount].VirtualAddress = secttbl[sectcount - 1].VirtualAddress + secttbl[sectcount - 1].Misc.VirtualSize;
    if (secttbl[sectcount].VirtualAddress % sectionalignment)
    {
        secttbl[sectcount].VirtualAddress += sectionalignment - (secttbl[sectcount].VirtualAddress % sectionalignment);
    }
    secttbl[sectcount].SizeOfRawData = sectionsize;
    if (secttbl[sectcount].SizeOfRawData % filealignment)
    {
        secttbl[sectcount].SizeOfRawData += filealignment - (secttbl[sectcount].SizeOfRawData % filealignment);
    }
    secttbl[sectcount].PointerToRawData = secttbl[sectcount - 1].PointerToRawData + secttbl[sectcount - 1].SizeOfRawData;
    if (secttbl[sectcount].PointerToRawData % filealignment)
    {
        secttbl[sectcount].PointerToRawData += filealignment - (secttbl[sectcount].PointerToRawData % filealignment);
    }
    secttbl[sectcount].Characteristics = sectioncharacteristics;

    /* grow the memory to accomodate the new section */
    pefile_len = secttbl[sectcount].PointerToRawData + secttbl[sectcount].SizeOfRawData;
    tmpbuff = realloc(pefile, (size_t)pefile_len);
    if (!tmpbuff)
    {
        free(pefile);
        return TMEMORY;
    }
    pefile = tmpbuff;

    /* increment the section count */
    write_le16(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                          FileHeader
                                         )
                               + offsetof(TAG_IMAGE_FILE_HEADER,
                                          NumberOfSections
                                         )
               , sectcount + 1);

    /* update the image size */
    write_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                          OptionalHeader
                                         )
                               + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                          SizeOfImage
                                         )
               , secttbl[sectcount].VirtualAddress + secttbl[sectcount].Misc.VirtualSize);

    /* copy the section data */
    memcpy(pefile + secttbl[sectcount].PointerToRawData, sectioncontent, sectionsize);

    /* save to file */
    if ((create_tmp_file(filename,
                         pefile,
                         pefile_len
                        )
        ) != ERR_NONE
       )
    {
        free(pefile);
        return TFILEACCESSDENIED;
    }

    free(pefile);
    return TNOERR;
}

