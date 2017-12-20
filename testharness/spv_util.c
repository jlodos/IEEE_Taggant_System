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

#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pe_util.h"
#include "file_util.h"
#include "lib_util.h"
#include "err.h"
#include "test.h"
#include "taggantlib.h"

extern UNSIGNED32(STDCALL *pTaggantObjectNewEx) (_In_opt_ PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, _Outptr_ PTAGGANTOBJ *pTaggantObj);
extern PPACKERINFO(STDCALL *pTaggantPackerInfo) (_In_ PTAGGANTOBJ pTaggantObj);
extern UNSIGNED32(STDCALL *pTaggantAddHashRegion) (_Inout_ PTAGGANTOBJ pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength);
extern UNSIGNED32(STDCALL *pTaggantComputeHashes) (_Inout_ PTAGGANTCONTEXT pCtx, _Inout_ PTAGGANTOBJ pTaggantObj, _In_ PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize);
extern UNSIGNED32(STDCALL *pTaggantPutInfo) (_Inout_ PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, UNSIGNED16 Size, _In_reads_(Size) PINFO pInfo);
extern UNSIGNED32(STDCALL *pTaggantPutTimestamp) (_Inout_ PTAGGANTOBJ pTaggantObj, _In_z_ const char* pTSUrl, UNSIGNED32 uTimeout);
extern UNSIGNED32(STDCALL *pTaggantPrepare) (_Inout_ PTAGGANTOBJ pTaggantObj, _In_ const PVOID pLicense, _Out_writes_bytes_(*uTaggantReservedSize) PVOID pTaggantOut, _Inout_updates_(1) UNSIGNED32 *uTaggantReservedSize);
extern void (STDCALL *pTaggantObjectFree) (_Post_ptr_invalid_ PTAGGANTOBJ pTaggantObj);

#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE 1
#endif

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
#endif

int erase_v1_taggant(_In_z_ const char *filename,
                     UNSIGNED8 **ppefile,
                     _Out_writes_(1) UNSIGNED64 *ppefile_len,
                     UNSIGNED32 *ptag_len
                    )
{
    int result;
    UNSIGNED64 peobj_len, pefixedobj_len;
    UNSIGNED64 tag_off;

    if ((result = read_tmp_file(filename,
                                ppefile,
                                ppefile_len
                               )
        ) == ERR_NONE
       )
    {
        if ((result = object_sizes(*ppefile,
                                   *ppefile_len,
                                   &peobj_len,
                                   &pefixedobj_len,
                                   &tag_off,
                                   ptag_len
                                  )
            ) != ERR_NONE
           )
        {
            free(*ppefile);
        }
        else
        {
            memset(*ppefile + tag_off,
                   0,
                   *ptag_len - sizeof(TAGGANT_MARKER_END)
                  );
        }
    }

    return result;
}


int add_hashmap(_In_ FILE *tagfile,
                _In_ PTAGGANTOBJ object,
                int badhash
               )
{
    int result;
    UNSIGNED8 lfanew[4];
    UNSIGNED8 opthdrsize[2];

    result = ERR_BADFILE;

    if (!fseek(tagfile,
               offsetof(TAG_IMAGE_DOS_HEADER,
                        e_lfanew
                       ),
               SEEK_SET
              )
     && (fread(lfanew,
               1,
               sizeof(lfanew),
               tagfile
              ) == sizeof(lfanew)
        )
     && !fseek(tagfile,
               read_le32(lfanew) + offsetof(TAG_IMAGE_NT_HEADERS32,
                                            FileHeader
                                           )
                                 + offsetof(TAG_IMAGE_FILE_HEADER,
                                            SizeOfOptionalHeader
                                           ),
               SEEK_SET
              )
     && (fread(opthdrsize,
               1,
               sizeof(opthdrsize),
               tagfile
              ) == sizeof(opthdrsize)
        )
       )
    {
        if ((result = pTaggantAddHashRegion(object,
                                            offsetof(TAG_IMAGE_DOS_HEADER,
                                                     e_lfanew
                                                    ),
                                            sizeof(lfanew)
                                           )
            ) == TNOERR
           )
        {
            result = pTaggantAddHashRegion(object,
                                           read_le32(lfanew),
                                           badhash ? 0 : (offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                   OptionalHeader
                                                                  )
                                                        + read_le16(opthdrsize)
                                                         )
                                          );
        }
    }

    return result;
}

int create_taggant(_In_z_ const char *filename,
                   const char *outfilename,
                   _In_ const PTAGGANTCONTEXT context,
                   UNSIGNED64 version,
                   TAGGANTCONTAINER tagtype, 
                   _In_z_ const UNSIGNED8 *licdata,
                   UNSIGNED64 peobj_len,
                   UNSIGNED64 file_len,
                   UNSIGNED64 tag_off,
                   UNSIGNED32 tag_len,
                   int hashmap,
                   int badhash,
                   int puttime,
                   int filleb
                  )
{
    int result;
    FILE *tagfile;
    PTAGGANTOBJ object;

    result = ERR_BADFILE;

    if (!fopen_s(&tagfile,
                 filename,
                 "rb+"
                )
     && tagfile
       )
    {
        object = NULL;

        if ((result = pTaggantObjectNewEx(NULL,
                                          version,
                                          tagtype,
                                          &object
                                         )
            ) == TNOERR
           )
        {
            PPACKERINFO packer_info;
            UNSIGNED8 *taggant;

            if (hashmap)
            {
                result = add_hashmap(tagfile,
                                     object,
                                     badhash
                                    );
            }

            if ((result == ERR_NONE)
             && filleb
               )
            {
                PINFO buffer;

                result = ERR_NOMEM;

                if ((buffer = (PINFO) malloc(0x10000 - 5)) != NULL)
                {
                    memset(buffer,
                           0xdd,
                           0x10000 - 5
                          );
                    result = pTaggantPutInfo(object,
                                             ECONTRIBUTORLIST,
                                             0x10000 - 5,
                                             buffer
                                            );
                    free(buffer);
                }
            }

            if ((result == ERR_NONE)
             && ((result = pTaggantComputeHashes(context,
                                                 object,
                                                 (PFILEOBJECT) tagfile,
                                                 peobj_len,
                                                 file_len,
                                                 tag_len
                                                )
                 ) == TNOERR
                )
               )
            {
                packer_info = pTaggantPackerInfo(object);
                packer_info->PackerId = PACKER_ID;
                packer_info->VersionMajor = PACKER_MAJOR;
                packer_info->VersionMinor = PACKER_MINOR;
                packer_info->VersionBuild = PACKER_BUILD;
                packer_info->Reserved = 0;

                if (!puttime
                 || ((result = pTaggantPutTimestamp(object,
                                                    "http://taggant-tsa.ieee.org/",
                                                    50
                                                   )
                     ) == TNOERR
                    )
                   )
                {
                    if (!tag_len)
                    {
                        tag_len = TAGGANT_MINIMUM_SIZE;
                    }

                    result = ERR_NOMEM;

                    if ((taggant = (UNSIGNED8 *) malloc(tag_len)) != NULL)
                    {
                        if (((result = pTaggantPrepare(object,
                                                       licdata,
                                                       taggant,
                                                       &tag_len
                                                      )
                             ) == TINSUFFICIENTBUFFER
                            )
                         && (version != TAGGANT_LIBRARY_VERSION1)
                           )
                        {
                            UNSIGNED8 *tmpbuff;

                            result = ERR_NOMEM;

                            if ((tmpbuff = (UNSIGNED8 *) realloc(taggant,
                                                                 tag_len
                                                                )
                                ) != NULL
                               )
                            {
                                result = pTaggantPrepare(object,
                                                         licdata,
                                                         taggant = tmpbuff,
                                                         &tag_len
                                                        );
                            }
                        }

                        if (result == ERR_NONE)
                        {
                            if (outfilename)
                            {
                                fclose(tagfile);
                                tagfile = NULL;
                                if (fopen_s(&tagfile, outfilename, "wb+") || !tagfile)
                                {
                                    result = ERR_BADFILE;
                                }
                            }
                            if (result == ERR_NONE)
                            {
                                result = ERR_BADFILE;
                                if (!fseek(tagfile,
                                           (long) tag_off,
                                           (version == TAGGANT_LIBRARY_VERSION1) ? SEEK_SET : SEEK_END
                                          )
                                 && (fwrite(taggant,
                                            1,
                                            tag_len,
                                            tagfile
                                           ) == tag_len
                                    )
                                   )
                                {
                                    result = ERR_NONE;
                                }
                            }
                        }

                        free(taggant);
                    }
                }
            }

            pTaggantObjectFree(object);
        }

        if (tagfile)
            fclose(tagfile);
    }

    return result;
}

int create_v1_taggant(_In_z_ const char *filename,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 file_len,
                      UNSIGNED64 tag_off,
                      UNSIGNED32 tag_len,
                      int hashmap,
                      int badhash,
                      int puttime
                     )
{
    return create_taggant(filename,
                          NULL,
                          context,
                          TAGGANT_LIBRARY_VERSION1,
                          TAGGANT_PEFILE, 
                          licdata,
                          peobj_len,
                          file_len,
                          tag_off,
                          tag_len,
                          hashmap,
                          badhash,
                          puttime,
                          FALSE
                         );
}

int create_v1_v1_taggant(_In_z_ const char *filename1,
                         _In_z_ const char *filename2,
                         _In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 obj_len,
                         UNSIGNED64 file_len,
                         int puttime
                        )
{
    int result;
    const UNSIGNED8 *tmpfile;
    UNSIGNED64 pefile_len;

    if ((result = read_tmp_file(filename1,
                                (UNSIGNED8 **) &tmpfile,
                                &pefile_len
                               )
        ) == ERR_NONE
       )
    {
        UNSIGNED64 peobj_len, pefixedobj_len;
        UNSIGNED64 tag_off;
        UNSIGNED32 tag_len;

        if (((result = object_sizes(tmpfile,
                                    pefile_len,
                                    &peobj_len,
                                    &pefixedobj_len,
                                    &tag_off,
                                    &tag_len
                                   )
             ) == ERR_NONE
            )
         && ((result = create_tmp_file(filename2,
                                       tmpfile,
                                       pefile_len
                                      )
             ) == ERR_NONE
            )
           )
        {
            result = create_v1_taggant(filename2,
                                       context,
                                       licdata,
                                       obj_len ? pefixedobj_len : 0,
                                       file_len,
                                       tag_off,
                                       tag_len,
                                       FALSE,
                                       FALSE,
                                       puttime
                                      );
        }

        free((PVOID) tmpfile);
    }

    return result;
}

int create_v2_taggant(_In_z_ const char *filename,
                      _In_ const PTAGGANTCONTEXT context,
                      TAGGANTCONTAINER tagtype, 
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 file_len,
                      int hashmap,
                      int badhash,
                      int puttime,
                      int filleb
                     )
{
    return create_taggant(filename,
                          NULL,
                          context,
                          TAGGANT_LIBRARY_VERSION2,
                          tagtype, 
                          licdata,
                          peobj_len,
                          file_len,
                          0,
                          0,
                          hashmap,
                          badhash,
                          puttime,
                          filleb
                         );
}

int create_v2_taggant_taggant(_In_z_ const char *filename1,
                              _In_z_ const char *filename2,
                              _In_ const PTAGGANTCONTEXT context,
                              TAGGANTCONTAINER tagtype, 
                              _In_z_ const UNSIGNED8 *licdata,
                              UNSIGNED64 peobj_len,
                              int puttime,
                              int filleb
                             )
{
    int result;
    const UNSIGNED8 *tmpfile;
    UNSIGNED64 pefile_len;

    if ((result = read_tmp_file(filename1,
                                (UNSIGNED8 **) &tmpfile,
                                &pefile_len
                               )
        ) == ERR_NONE
       )
    {
        if ((result = create_tmp_file(filename2,
                                      tmpfile,
                                      pefile_len
                                     )
            ) == ERR_NONE
           )
        {
            result = create_v2_taggant(filename2,
                                       context,
                                       tagtype,
                                       licdata,
                                       peobj_len,
                                       0,
                                       FALSE,
                                       FALSE,
                                       puttime,
                                       filleb
                                      );
        }

        free((PVOID) tmpfile);
    }

    return result;
}

int create_tmp_v1_taggant(_In_z_ const char *filename,
                          _In_ const PTAGGANTCONTEXT context,
                          _In_z_ const UNSIGNED8 *licdata,
                          _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                          UNSIGNED64 peobj_len,
                          UNSIGNED64 pefile_len,
                          UNSIGNED64 file_len,
                          UNSIGNED64 tag_off,
                          UNSIGNED32 tag_len,
                          int hashmap,
                          int puttime
                         )
{
    int result;

    if ((result = create_tmp_file(filename,
                                  pefile,
                                  pefile_len
                                 )
        ) == ERR_NONE
       )
    {
        result = create_v1_taggant(filename,
                                   context,
                                   licdata,
                                   peobj_len,
                                   file_len,
                                   tag_off,
                                   tag_len,
                                   hashmap,
                                   FALSE,
                                   puttime
                                  );
    }

    return result;
}

int create_tmp_v1_v2_taggant(_In_z_ const char *filename1,
                             _In_z_ const char *filename2,
                             _In_ const PTAGGANTCONTEXT context,
                             _In_z_ const UNSIGNED8 *licdata,
                             UNSIGNED64 peobj_len,
                             UNSIGNED64 tag_off,
                             int puttime
                            )
{
    int result;
    UNSIGNED8 *tmpfile;
    UNSIGNED64 tmpfile_len;
    UNSIGNED32 tag_len;

    if ((result = erase_v1_taggant(filename1,
                                   &tmpfile,
                                   &tmpfile_len,
                                   &tag_len
                                  )
        ) == ERR_NONE
       )
    {
        if (((result = create_tmp_file(filename2,
                                       tmpfile,
                                       tmpfile_len
                                      )
             ) == ERR_NONE
            )
         && ((result = create_v2_taggant(filename2,
                                         context,
                                         TAGGANT_PEFILE,
                                         licdata,
                                         peobj_len,
                                         0,
                                         FALSE,
                                         FALSE,
                                         puttime,
                                         FALSE
                                        )
             ) == ERR_NONE
            )
           )
        {
            result = create_v1_taggant(filename2,
                                       context,
                                       licdata,
                                       peobj_len,
                                       0,
                                       tag_off,
                                       tag_len,
                                       FALSE,
                                       FALSE,
                                       puttime
                                      );
        }

        free(tmpfile);
    }

    return result;
}

int append_v1_taggant(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 tag_off
                     )
{
    int result;
    unsigned char *tmpfile;
    UNSIGNED64 tmpfile_len;
    UNSIGNED32 tag_len;

    if ((result = erase_v1_taggant(filename1,
                                   &tmpfile,
                                   &tmpfile_len,
                                   &tag_len
                                  )
        ) == ERR_NONE
       )
    {
        if ((result = append_file(filename2,
                                  tmpfile,
                                  tmpfile_len,
                                  ERR_BADFILE
                                 )
            ) == ERR_NONE
           )
        {
            result = create_v1_taggant(filename2,
                                       context,
                                       licdata,
                                       peobj_len,
                                       tmpfile_len,
                                       tag_off,
                                       tag_len,
                                       FALSE,
                                       FALSE,
                                       FALSE
                                      );
        }

        free(tmpfile);
    }

    return result;
}

int append_v1_v2_taggant(_In_z_ const char *filename1,
                         _In_z_ const char *filename2,
                         _In_ const PTAGGANTCONTEXT context,
                         _In_z_ const UNSIGNED8 *licdata,
                         UNSIGNED64 peobj_len,
                         UNSIGNED64 tag_off
                        )
{
    int result;
    UNSIGNED8 *tmpfile;
    UNSIGNED64 tmpfile_len;
    UNSIGNED32 tag_len;

    if ((result = erase_v1_taggant(filename1,
                                   &tmpfile,
                                   &tmpfile_len,
                                   &tag_len
                                  )
        ) == ERR_NONE
       )
    {
        if (((result = append_file(filename2,
                                   tmpfile,
                                   tmpfile_len,
                                   ERR_BADFILE
                                  )
             ) == ERR_NONE
            )
         && ((result = create_v2_taggant(filename2,
                                         context,
                                         TAGGANT_PEFILE,
                                         licdata,
                                         peobj_len,
                                         tmpfile_len,
                                         FALSE,
                                         FALSE,
                                         FALSE,
                                         FALSE
                                        )
             ) == ERR_NONE
            )
           )
        {
            result = create_v1_taggant(filename2,
                                       context,
                                       licdata,
                                       peobj_len,
                                       0,
                                       tag_off,
                                       tag_len,
                                       FALSE,
                                       FALSE,
                                       FALSE
                                      );
        }

        free(tmpfile);
    }

    return result;
}

int create_tampered_v1_image(_In_z_ const char *filename1,
                             _In_z_ const char *filename2,
                             _In_z_ const char *filename3,
                             const PTAGGANTCONTEXT context,
                             const UNSIGNED8 *licdata,
                             int tamper1,
                             int tamper2
                            )
{
    int result;
    unsigned char *tmpfile;
    UNSIGNED64 tmpfile_len;
    UNSIGNED64 peobj_len, pefixedobj_len;
    UNSIGNED64 tag_off;
    UNSIGNED32 tag_len;

    if ((result = read_tmp_file(filename1,
                                &tmpfile,
                                &tmpfile_len
                               )
        ) == ERR_NONE
       )
    {
        if ((result = object_sizes(tmpfile,
                                   tmpfile_len,
                                   &peobj_len,
                                   &pefixedobj_len,
                                   &tag_off,
                                   &tag_len
                                  )
            ) == ERR_NONE
           )
        {
            tmpfile[tag_off + 0x100] += (unsigned char) tamper1;
            tmpfile[2] += (unsigned char) tamper2;

            if ((result = create_tmp_file(filename2,
                                          tmpfile,
                                          tmpfile_len
                                         )
                ) == ERR_NONE
               )
            {
                result = create_v1_v1_taggant(filename2,
                                              filename3,
                                              context,
                                              licdata,
                                              0,
                                              0,
                                              FALSE
                                             );
            }
        }

        free(tmpfile);
    }

    return result;
}

int create_tampered_v1_v2_image(_In_z_ const char *filename1,
                                _In_z_ const char *filename2,
                                _In_z_ const char *filename3,
                                _In_ const PTAGGANTCONTEXT context,
                                _In_z_ const UNSIGNED8 *licdata,
                                UNSIGNED64 peobj_len,
                                UNSIGNED64 tag_off,
                                int badhash,
                                UNSIGNED64 tamper_off
                               )
{
    int result;
    UNSIGNED8 *tmpfile1;
    UNSIGNED64 tmpfile1_len;
    UNSIGNED32 tag_len;

    if (((result = erase_v1_taggant(filename1,
                                    &tmpfile1,
                                    &tmpfile1_len,
                                    &tag_len
                                   )
         ) == ERR_NONE
        )
       )
    {
        UNSIGNED8 *tmpfile2;
        UNSIGNED64 tmpfile2_len;

        if (((result = create_tmp_file(filename2,
                                       tmpfile1,
                                       tmpfile1_len
                                      )
             ) == ERR_NONE
            )
         && ((result = create_v2_taggant(filename2,
                                         context,
                                         TAGGANT_PEFILE,
                                         licdata,
                                         peobj_len,
                                         0,
                                         badhash,
                                         badhash,
                                         FALSE,
                                         FALSE
                                        )
             ) == ERR_NONE
            )
         && ((result = read_tmp_file(filename2,
                                     &tmpfile2,
                                     &tmpfile2_len
                                    )
             ) == ERR_NONE
            )
           )
        {
            if (!badhash)
            {
                if ((SIGNED64) tamper_off < 0)
                {
                    tamper_off += tmpfile2_len;
                }

                ++tmpfile2[tamper_off];
            }

            if ((result = create_tmp_file(filename3,
                                          tmpfile2,
                                          tmpfile2_len
                                         )
                ) == ERR_NONE
               )
            {
                result = create_v1_taggant(filename3,
                                           context,
                                           licdata,
                                           peobj_len,
                                           0,
                                           tag_off,
                                           tag_len,
                                           FALSE,
                                           FALSE,
                                           FALSE
                                          );
            }

            free(tmpfile2);
        }

        free(tmpfile1);
    }

    return result;
}

int create_bad_v1_hmh(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 pefile_len,
                      UNSIGNED64 file_len,
                      UNSIGNED64 tag_off,
                      UNSIGNED32 tag_len
                     )
{
    int result;

    if ((result = create_tmp_file(filename1,
                                  pefile,
                                  pefile_len
                                 )
        ) == ERR_NONE
       )
    {
        if ((result = create_v1_taggant(filename1,
                                        context,
                                        licdata,
                                        peobj_len,
                                        file_len,
                                        tag_off,
                                        tag_len,
                                        TRUE,
                                        TRUE,
                                        FALSE
                                       )
            ) == ERR_NONE
           )
        {
            result = create_v1_v1_taggant(filename1,
                                          filename2,
                                          context,
                                          licdata,
                                          0,
                                          0,
                                          FALSE
                                         );
        }
    }

    return result;
}

int create_tmp_v2_taggant(_In_z_ const char *filename,
                          _In_ const PTAGGANTCONTEXT context,
                          TAGGANTCONTAINER tagtype,
                          _In_z_ const UNSIGNED8 *licdata,
                          _In_reads_(tmpfile_len) const UNSIGNED8 *tmpfile,
                          UNSIGNED64 peobj_len,
                          UNSIGNED64 tmpfile_len,
                          int hashmap,
                          int puttime
                         )
{
    int result;

    if ((result = create_tmp_file(filename,
                                  tmpfile,
                                  tmpfile_len
                                 )
        ) == ERR_NONE
       )
    {
        result = create_v2_taggant(filename,
                                   context,
                                   tagtype,
                                   licdata,
                                   peobj_len,
                                   (tagtype == TAGGANT_PEFILE) ? 0 : tmpfile_len,
                                   hashmap,
                                   FALSE,
                                   puttime,
                                   FALSE
                                  );
    }

    return result;
}

int append_v2_taggant(_In_z_ const char *filename,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                      UNSIGNED64 peobj_len,
                      UNSIGNED64 pefile_len
                     )
{
    int result;

    if ((result = append_file(filename,
                              pefile,
                              pefile_len,
                              ERR_BADFILE
                             )
        ) == ERR_NONE
       )
    {
        result = create_v2_taggant(filename,
                                   context,
                                   TAGGANT_PEFILE,
                                   licdata,
                                   peobj_len,
                                   pefile_len,
                                   FALSE,
                                   FALSE,
                                   FALSE,
                                   FALSE
                                  );
    }

    return result;
}

int create_tampered_v2_image(_In_z_ const char *filename1,
                             _In_z_ const char *filename2,
                             const char *filename3,
                             const PTAGGANTCONTEXT context,
                             const UNSIGNED8 *licdata,
                             UNSIGNED64 peobj_len,
                             int tamper1,
                             int tamper2,
                             int csamode
                            )
{
    int result;
    unsigned char *tmpfile;
    UNSIGNED64 tmpfile_len;

    if ((result = read_tmp_file(filename1,
                                &tmpfile,
                                &tmpfile_len
                               )
        ) == ERR_NONE
       )
    {
        tmpfile[tmpfile_len - 0x100] += (unsigned char) tamper1;
        tmpfile[2] += (unsigned char) tamper2;

        if (((result = create_tmp_file(filename2,
                                       tmpfile,
                                       tmpfile_len
                                      )
             ) == ERR_NONE
            )
         && csamode
           )
        {
            result = create_v2_taggant_taggant(filename2,
                                               filename3,
                                               context,
                                               TAGGANT_PEFILE,
                                               licdata,
                                               peobj_len,
                                               FALSE,
                                               FALSE
                                              );
        }

        free(tmpfile);
    }

    return result;
}

int create_bad_v2_hmh(_In_z_ const char *filename1,
                      _In_z_ const char *filename2,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      UNSIGNED64 peobj_len
                     )
{
    return create_v2_taggant_taggant(filename1,
                                     filename2,
                                     context,
                                     TAGGANT_PEFILE,
                                     licdata,
                                     peobj_len,
                                     FALSE,
                                     FALSE
                                    );
}

int create_v3_taggant(_In_z_ const char *jsonfilename,
                      _In_z_ const char *outfilename,
                      _In_ const PTAGGANTCONTEXT context,
                      _In_z_ const UNSIGNED8 *licdata,
                      int puttime,
                      int filleb
                     )
{
    return create_taggant(jsonfilename,
                          outfilename,
                          context,
                          TAGGANT_LIBRARY_VERSION3,
                          TAGGANT_PESEALFILE, 
                          licdata,
                          0,
                          0,
                          0,
                          0,
                          0,
                          0,
                          puttime,
                          filleb
                         );
}


int create_tmp_v3_taggant(_In_z_ const char *filename,
                          _In_z_ const char *jsonfilename,
                          _In_z_ const char *taggantfilename,
                          _In_z_ const char *certfilename,
                          _In_z_ const char *certpwd,
                          _In_reads_(tmpfile_len) const UNSIGNED8 *tmpfile,
                          UNSIGNED64 tmpfile_len
                         )
{
    int result;
    FILE *tagfile;
    UNSIGNED8 *ptagdata;
    UNSIGNED64 taglen;
    UNSIGNED8 *pjsondata;
    UNSIGNED64 jsonlen;

    if ((result = create_tmp_file(filename,
                                  tmpfile,
                                  tmpfile_len
                                 )
        ) == ERR_NONE
       )
    {
        /* add JSON seal in a section*/
        if ((result = read_data_file(jsonfilename,
                                     &pjsondata,
                                     &jsonlen
                                    )
            ) == ERR_NONE
           )
        {
            result = add_section(filename, ".AESeal", pjsondata, (UNSIGNED32)jsonlen, 0x00000040 | 0x40000000); /* IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ */
            free(pjsondata);
        }

        /* add the taggant */
        if ((result = read_data_file(taggantfilename,
                                     &ptagdata,
                                     &taglen
                                    )
            ) == ERR_NONE
           )
        {
            result = ERR_BADFILE;

            if (!fopen_s(&tagfile,
                         filename,
                         "ab"
                        )
                 && tagfile
               )
            {
                if (fwrite(ptagdata,
                           1,
                           (size_t)taglen,
                           tagfile
                          ) == taglen
                   )
                {
                    result = ERR_NONE;
                }

                fclose(tagfile);
            }

            free(ptagdata);
        }

        /* sign */
        if (result == ERR_NONE)
        {
            if (!authenticode_sign(filename, certfilename, certpwd))
            {
                result = ERR_BADSIGNATURE;
            }
        }
    }

    return result;
}

int duplicate_tag(_In_z_ const char *filename,
                  _In_z_ const UNSIGNED8 *licdata,
                  _In_reads_(pefile_len) const UNSIGNED8 *pefile,
                  UNSIGNED64 pefile_len
                 )
{
    int result;
    unsigned int size;
    char buffer[max(sizeof(TESTSTRING1), sizeof(TESTSTRING2))];
    PTAGGANTOBJ object;

    object = NULL;
    size = sizeof(buffer);

    if (((result = pTaggantObjectNewEx(NULL,
                                       TAGGANT_LIBRARY_VERSION2,
                                       TAGGANT_PEFILE,
                                       &object
                                      )
         ) == TNOERR
        )
     && ((result = pTaggantPutInfo(object,
                                   ECONTRIBUTORLIST,
                                   sizeof(TESTSTRING1),
                                   TESTSTRING1
                                  )
         ) == TNOERR
        )
     && ((result = pTaggantPutInfo(object,
                                   ECONTRIBUTORLIST,
                                   sizeof(TESTSTRING2),
                                   TESTSTRING2
                                  )
         ) == TNOERR
        )
       )
    {
        FILE *tagfile;
        UNSIGNED32 tag_len;
        UNSIGNED8 *taggant;

        result = ERR_BADFILE;

        if (!fopen_s(&tagfile,
                     filename,
                     "wb+"
                    )
         && tagfile
           )
        {
            if (fwrite(pefile,
                       1,
                       (size_t) pefile_len,
                       tagfile
                      ) == pefile_len
                )
            {
                result = ERR_NOMEM;

                if ((taggant = (UNSIGNED8 *) malloc(tag_len = TAGGANT_MINIMUM_SIZE)) != NULL)
                {
                    if ((result = pTaggantPrepare(object,
                                                  licdata,
                                                  taggant,
                                                  &tag_len
                                                 )
                        ) != TNOERR
                       )
                    {
                        if (result == TINSUFFICIENTBUFFER)
                        {
                            UNSIGNED8 *tmpbuff;

                            result = ERR_NOMEM;

                            if ((tmpbuff = (UNSIGNED8 *) realloc(taggant,
                                                                 tag_len
                                                                )
                                ) != NULL
                               )
                            {
                                result = pTaggantPrepare(object,
                                                         licdata,
                                                         taggant = tmpbuff,
                                                         &tag_len
                                                        );
                            }
                        }    
                    }

                    if ((result == ERR_NONE)
                     && (fwrite(taggant,
                                1,
                                tag_len,
                                tagfile
                               ) != tag_len
                        )
                       )
                    {
                        result = ERR_BADFILE;
                    }

                    free(taggant);
                }
            }

            fclose(tagfile);
        }
    }

    pTaggantObjectFree(object);

    return result;
}

int create_ds(_In_z_ const char *filename1,
              _In_z_ const char *filename2,
              int mode64
             )
{
    int result;
    UNSIGNED8 *tmpfile, padding;
    UNSIGNED64 tmpfile_len;

    if ((result = read_tmp_file(filename1,
                                &tmpfile,
                                &tmpfile_len
                               )
        ) == ERR_NONE
       )
    {
        PTAG_IMAGE_DATA_DIRECTORY secdir;

        secdir = (PTAG_IMAGE_DATA_DIRECTORY) (tmpfile + read_le32(tmpfile + offsetof(TAG_IMAGE_DOS_HEADER,
                                                                                     e_lfanew
                                                                                    )
                                                                 ) + (mode64 ? (offsetof(TAG_IMAGE_NT_HEADERS64,
                                                                                         OptionalHeader
                                                                                        ) + offsetof(TAG_IMAGE_OPTIONAL_HEADER64,
                                                                                                     DataDirectory[4] /* TAG_IMAGE_DIRECTORY_ENTRY_SECURITY */
                                                                                                    )
                                                                               ) :
                                                                               (offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                                         OptionalHeader
                                                                                        ) + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                                                                     DataDirectory[4] /* IMAGE_DIRECTORY_ENTRY_SECURITY */
                                                                                                    )
                                                                               )
                                                                     )
                                         );
        secdir->VirtualAddress = (UNSIGNED32) tmpfile_len;
        /* pad to 8 byte boundary as per PE/COFF specification */
        padding = secdir->VirtualAddress % 8;
        if (padding)
        {
            padding = 8 - padding;
            secdir->VirtualAddress += padding;
        }
        secdir->Size = 1;
        for (; padding && result == ERR_NONE; --padding)
        {
            result = append_file(filename2,
                                 tmpfile,
                                 tmpfile_len,
                                 0
                                );
            free(tmpfile);
            if ((result = read_tmp_file(filename2,
                                        &tmpfile,
                                        &tmpfile_len
                                       )
                ) != ERR_NONE
               )
            {
                tmpfile = NULL;
                break;
            }
        }
        if (result == ERR_NONE)
        {
            result = append_file(filename2,
                                 tmpfile,
                                 tmpfile_len,
                                 ERR_BADFILE
                                );
        }
        free(tmpfile);
    }

    return result;
}

int create_eof(_In_z_ const char *filename,
               _In_ const PTAGGANTCONTEXT context,
               _In_z_ const UNSIGNED8 *licdata,
               const UNSIGNED8 *pefile,
               UNSIGNED64 peobj_len,
               UNSIGNED64 pefile_len
              )
{
    int result;
    UNSIGNED8 *tmpfile;
    UNSIGNED64 tmpfile_len;

    result = ERR_NOMEM;

    if ((tmpfile = (UNSIGNED8 *) malloc((size_t) pefile_len)) != NULL)
    {
        UNSIGNED8 *tagptr;
        UNSIGNED32 lfanew;

        lfanew = read_le32(pefile + offsetof(TAG_IMAGE_DOS_HEADER,
                                             e_lfanew
                                            )
                          );

        tagptr = (UNSIGNED8 *) memcpy(tmpfile,
                                      pefile,
                                      (size_t) pefile_len
                                     )
               + virttophys(pefile_len,
                            (TAG_IMAGE_SECTION_HEADER *) (pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                                     OptionalHeader
                                                                                    ) + read_le16(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                                                                             FileHeader
                                                                                                                            )
                                                                                                                  + offsetof(TAG_IMAGE_FILE_HEADER,
                                                                                                                             SizeOfOptionalHeader
                                                                                                                            )
                                                                                                 )
                                                     ),
                            read_le16(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                 FileHeader
                                                                )
                                                      + offsetof(TAG_IMAGE_FILE_HEADER,
                                                                 NumberOfSections
                                                                )
                                     ),
                            read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                 OptionalHeader
                                                                )
                                                      + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                                 AddressOfEntryPoint
                                                                )
                                     ),
                            read_le32(pefile + lfanew + offsetof(TAG_IMAGE_NT_HEADERS32,
                                                                 OptionalHeader
                                                                )
                                                      + offsetof(TAG_IMAGE_OPTIONAL_HEADER32,
                                                                 FileAlignment
                                                                )
                                     ),
                            &peobj_len
                           );
        fix_image_size(pefile, pefile_len, peobj_len, &peobj_len);
        tagptr[2] = (UNSIGNED8) (tmpfile_len = pefile_len + TAGGANT_MINIMUM_SIZE);
        tagptr[3] = (UNSIGNED8) (tmpfile_len >> 8);
        tagptr[4] = (UNSIGNED8) (tmpfile_len >> 16);
        tagptr[5] = (UNSIGNED8) (tmpfile_len >> 24);
        result = append_v2_taggant(filename,
                                   context,
                                   licdata,
                                   tmpfile,
                                   peobj_len,
                                   pefile_len
                                  );
        free(tmpfile);

        if ((result == ERR_NONE)
         && ((result = read_tmp_file(filename,
                                     &tmpfile,
                                     &tmpfile_len
                                    )
             ) == ERR_NONE
            )
           )
        {
            UNSIGNED8 *tmpbuff;

            result = ERR_NOMEM;

            if ((tmpbuff = (UNSIGNED8 *) realloc(tmpfile,
                                                 (size_t) pefile_len + TAGGANT_MINIMUM_SIZE
                                                )
                ) != NULL
               )
            {
                UNSIGNED32 taglen;

                taglen = read_le32(tmpbuff + tmpfile_len - (sizeof(TAGGANT_HEADER2) - offsetof(TAGGANT_HEADER2,
                                                                                               TaggantLength
                                                                                              )
                                                           )
                                  );
                tmpfile = tmpbuff;
                memmove(tmpfile + pefile_len + TAGGANT_MINIMUM_SIZE - taglen,
                        tmpfile + tmpfile_len - taglen,
                        taglen
                       );
                memset(tmpfile + pefile_len,
                       0,
                       TAGGANT_MINIMUM_SIZE - taglen
                      );
                /* After appending data peobj_len may have changed if the last section had a 
                   real size smaller than indicated by the headers */
                result = object_sizes(tmpfile, pefile_len + TAGGANT_MINIMUM_SIZE, &peobj_len, &peobj_len, NULL, NULL);
				if (result == ERR_NONE)
                {
                    result = create_tmp_v1_taggant(filename,
                                                   context,
                                                   licdata,
                                                   tmpfile,
                                                   peobj_len,
                                                   pefile_len + TAGGANT_MINIMUM_SIZE,
                                                   pefile_len + TAGGANT_MINIMUM_SIZE,
                                                   pefile_len + TAGGANT_MINIMUM_SIZE,
                                                   0,
                                                   FALSE,
                                                   FALSE
                                                  );
                }
            }

            free(tmpfile);
        }
    }

    return result;
}
