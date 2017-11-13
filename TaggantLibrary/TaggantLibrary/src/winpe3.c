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
#include <stdarg.h>

#if defined(SSV_SEAL_LIBRARY) || defined(SPV_SEAL_LIBRARY)

#include "callbacks.h"
#include "winpe.h"
#include "winpe3.h"
#include "miscellaneous.h"
#include "endianness.h"

#define TBL_MODULE                  0x00
#define TBL_TYPEREF                 0x01
#define TBL_TYPEDEF                 0x02
#define TBL_FIELDPTR                0x03
#define TBL_FIELD                   0x04
#define TBL_METHODDEFPTR            0x05
#define TBL_METHODDEF               0x06
#define TBL_PARAMPTR                0x07
#define TBL_PARAM                   0x08
#define TBL_INTERFACEIMPL           0x09
#define TBL_MEMBERREF               0x0A
#define TBL_CONSTANT                0x0B
#define TBL_CUSTOMATTRIBUTE         0x0C
#define TBL_FIELDMARSHAL            0x0D
#define TBL_DECLSECURITY            0x0E
#define TBL_CLASSLAYOUT             0x0F
#define TBL_FIELDLAYOUT             0x10
#define TBL_STANDALONESIG           0x11
#define TBL_EVENTMAP                0x12
#define TBL_EVENTPTR                0x13
#define TBL_EVENT                   0x14
#define TBL_PROPERTYMAP             0x15
#define TBL_PROPERTYPTR             0x16
#define TBL_PROPERTY                0x17
#define TBL_METHODSEMANTICS         0x18
#define TBL_METHODIMPL              0x19
#define TBL_MODULEREF               0x1A
#define TBL_TYPESPEC                0x1B
#define TBL_IMPLMAP                 0x1C
#define TBL_FIELDRVA                0x1D
#define TBL_ENCLOG                  0x1E
#define TBL_ENCMAP                  0x1F
#define TBL_ASSEMBLY                0x20
#define TBL_ASSEMBLYPROCESSOR       0x21
#define TBL_ASSEMBLYOS              0x22
#define TBL_ASSEMBLYREF             0x23
#define TBL_ASSEMBLYREFPROCESSOR    0x24
#define TBL_ASSEMBLYREFOS           0x25
#define TBL_FILE                    0x26
#define TBL_EXPORTEDTYPE            0x27
#define TBL_MANIFESTRESOURCE        0x28
#define TBL_NESTEDCLASS             0x29
#define TBL_GENERICPARAM            0x2A
#define TBL_METHODSPEC              0x2B
#define TBL_GENERICPARAMCONSTRAINT  0x2C

int winpe_read_clr20_header(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, CLR_METADATA* clrh)
{
    unsigned long clr_va;

    clrh->file_size = peh->filesize;
    if (winpe_is_pe64(peh))
    {
        clr_va = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        clrh->cor20_size = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    }
    else
    {
        clr_va = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        clrh->cor20_size = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    }
    if (clr_va != 0 && clrh->cor20_size != 0)
    {
        /* initialize CLR header offset */
        if (winpe_va_to_raw(pCtx, fp, peh, clr_va, &clrh->cor20_offset))
        {
            /* make sure CLR header is read fully */
            if (!pCtx->FileSeekCallBack(fp, clrh->cor20_offset, SEEK_SET))
            {
                if (pCtx->FileReadCallBack(fp, &clrh->clrh, sizeof(TAG_IMAGE_COR20_HEADER)) == sizeof(TAG_IMAGE_COR20_HEADER))
                {
                    if (IS_BIG_ENDIAN)
                    {
                        clrh->clrh.MetaData.VirtualAddress = UNSIGNED32_to_big_endian((char*)&clrh->clrh.MetaData.VirtualAddress);
                        clrh->clrh.MetaData.Size = UNSIGNED32_to_big_endian((char*)&clrh->clrh.MetaData.Size);
                        clrh->clrh.Flags = UNSIGNED32_to_big_endian((char*)&clrh->clrh.Flags);
                        clrh->clrh.Resources.VirtualAddress = UNSIGNED32_to_big_endian((char*)&clrh->clrh.Resources.VirtualAddress);
                        clrh->clrh.Resources.Size = UNSIGNED32_to_big_endian((char*)&clrh->clrh.Resources.Size);
                    }
                    /* initialize resources offset */
                    if (winpe_va_to_raw(pCtx, fp, peh, clrh->clrh.Resources.VirtualAddress, &clrh->resources_offset))
                    {
                        /* initialize metadata offset */
                        if (winpe_va_to_raw(pCtx, fp, peh, clrh->clrh.MetaData.VirtualAddress, &clrh->metadata_offset))
                        {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

UNSIGNED32 winpe_metadata_table_index_size(CLR_METADATA* clrh, UNSIGNED8 bits, int indexes, ...)
{
    va_list va;
    int i;
    UNSIGNED32 max_rows, index;

    va_start(va, indexes);
    max_rows = clrh->rows_per_table[va_arg(va, UNSIGNED32)];
    for (i = 1; i < indexes; i++)
    {
        index = va_arg(va, UNSIGNED32);
        if (clrh->rows_per_table[index] > max_rows)
            max_rows = clrh->rows_per_table[index];
    }
    va_end(va);
    return (max_rows > (0xFFFFu >> bits)) ? 4 : 2;
}

int winpe_get_clr_blob(CLR_METADATA* clrh, char* ptr, char* buffer, UNSIGNED32* offset, UNSIGNED32* length)
{
    /* The blob size is encoded in the first 1, 2 or 4 bytes of the blob.
     If the high bit is not set the length is encoded in one byte.
     If the high 2 bits are 10 the length is encoded in the other bits
     and the next byte.
     If the high 3 bits are 110 the length is encoded in the other bits
     and the next 3 bytes. */

    if ((*ptr & 0x80) == 0x00)
    {
        /* 1 byte encoding */
        *offset = (UNSIGNED32)(ptr + 1 - buffer - clrh->metadata_offset);
        *length = *ptr;
        return *offset + *length < clrh->metadata_offset + clrh->clrh.MetaData.Size;
    }

    if (ptr + 1 < buffer + clrh->clrh.MetaData.Size)
    {
        if ((*ptr & 0xC0) == 0x80)
        {
            /* 2 byte encoding */
            *offset = (UNSIGNED32)(ptr + 2 - buffer - clrh->metadata_offset);
            *length = ((*ptr & 0x3F) << 16) + *(ptr + 1);
            return *offset + *length < clrh->metadata_offset + clrh->clrh.MetaData.Size;
        }
    }

    if (ptr + 4 < buffer + clrh->clrh.MetaData.Size)
    {
        if ((*ptr & 0xE0) == 0xC0)
        {
            /* 4 byte encoding */
            *offset = (UNSIGNED32)(ptr + 4 - buffer - clrh->metadata_offset);
            *length = ((*ptr & 0x1F) << 24) | (*(ptr + 1) << 16) | (*(ptr + 2) << 8) | *(ptr + 3);
            return *offset + *length < clrh->metadata_offset + clrh->clrh.MetaData.Size;
        }
    }

    return 0;
}

void winpe_parse_custom_attribute_table(CLR_METADATA* clrh, char* buffer, char* ptr, UNSIGNED32 index_size1, UNSIGNED32 index_size2, UNSIGNED32 row_size)
{
    UNSIGNED32 parent_index, type_index, class_index;
    UNSIGNED8 parent_table, type_table, class_table;
    UNSIGNED32 blob_offset, name_offset, name_length;
    char *memberref_ptr, *typeref_ptr, *tmp;

    if (clrh->typeref_table.offset != 0 && clrh->memberref_table.offset != 0)
    {
        if (clrh->string_stream.offset != 0 && clrh->blob_stream.offset != 0)
        {
            for (unsigned long i = 0; i < clrh->rows_per_table[TBL_CUSTOMATTRIBUTE]; i++)
            {
                if (ptr + row_size > buffer + clrh->clrh.MetaData.Size)
                    break; /* overflow */

                /* the parent is a coded token of type HasCustomAttribute */
                if (index_size1 == 4)
                {
                    parent_index = UNSIGNED32_from_little_endian(ptr) >> 5;
                    parent_table = UNSIGNED32_from_little_endian(ptr) & 0x1F;
                }
                else
                {
                    parent_index = UNSIGNED16_from_little_endian(ptr) >> 5;
                    parent_table = UNSIGNED16_from_little_endian(ptr) & 0x1F;
                }
                /* in this application we want assembly attributes only */
                if (parent_table != 0x0E)
                {
                    ptr += row_size;
                    continue;
                }

                /* the type is a coded token of type CustomAttributeType */
                if (index_size2 == 4)
                {
                    type_index = UNSIGNED32_from_little_endian(ptr + index_size1) >> 3;
                    type_table = UNSIGNED32_from_little_endian(ptr + index_size1) & 0x07;
                }
                else
                {
                    type_index = UNSIGNED16_from_little_endian(ptr + index_size1) >> 3;
                    type_table = UNSIGNED16_from_little_endian(ptr + index_size1) & 0x07;
                }
                /* in this application we want MemberRef indexes only */
                if (type_table != 0x03)
                {
                    ptr += row_size;
                    continue;
                }
                if (type_index > 0)
                    type_index--;

                /* ignore rows with no value */
                if (clrh->flags & 4)
                    blob_offset = UNSIGNED32_from_little_endian(ptr + index_size1 + index_size2);
                else
                    blob_offset = UNSIGNED16_from_little_endian(ptr + index_size1 + index_size2);
                if (blob_offset == 0)
                {
                    ptr += row_size;
                    continue;
                }

                /* the class is a MemberRefParent coded index */
                memberref_ptr = buffer + clrh->memberref_table.row_size * type_index;
                if (clrh->rows_per_table[TBL_MEMBERREF] > 0xFFFF)
                {
                    class_index = UNSIGNED32_from_little_endian(memberref_ptr) >> 3;
                    class_table = UNSIGNED32_from_little_endian(memberref_ptr) & 0x07;
                }
                else
                {
                    class_index = UNSIGNED16_from_little_endian(memberref_ptr) >> 3;
                    class_table = UNSIGNED16_from_little_endian(memberref_ptr) & 0x07;
                }
                /* in this application we want TypeRef indexes only */
                if (class_table != 0x01)
                {
                    ptr += row_size;
                    continue;
                }
                if (class_index > 0)
                    class_index--;

                /* The index is a ResolutionScope coded index.
                   We are interested in the name, so skip the index. */
                typeref_ptr = buffer + clrh->typeref_table.row_size * class_index;
                typeref_ptr += clrh->typeref_table.dynamic_index_size;
                if (clrh->flags & 1)
                    name_offset = UNSIGNED32_from_little_endian(typeref_ptr);
                else
                    name_offset = UNSIGNED16_from_little_endian(typeref_ptr);
                if (clrh->string_stream.offset + name_offset >= clrh->clrh.MetaData.Size)
                {
                    ptr += row_size;
                    continue;
                }
                name_length = 0;
                tmp = buffer + name_offset;
                for (; *tmp; ++tmp, ++name_length)
                {
                    if (tmp >= buffer + clrh->clrh.MetaData.Size)
                    {
                        break;
                    }
                }
                if (0 == strncmp(buffer + name_offset, "AssemblyCompanyAttribute", name_length))
                {
                    if (winpe_get_clr_blob(clrh, ptr, buffer, &clrh->company.offset, &clrh->company.length))
                    {
                        /* Custom attributes must have a 16 bit prolog of 0x0001 */
                        if (UNSIGNED16_from_little_endian(buffer - clrh->metadata_offset + clrh->company.offset) == 0x0001)
                        {
                            clrh->company.offset += 2; /* skip the prolog */
                            /* The next byte is the length of the string. */
                            clrh->company.length = *(buffer - clrh->metadata_offset + clrh->company.offset);
                            if (clrh->company.offset + clrh->company.length < clrh->metadata_offset + clrh->clrh.MetaData.Size)
                            {
                                clrh->company.offset++; /* skip the length */
                            }
                        }
                    }
                }
                ptr += row_size;
                continue;
            }
        }
    }
}

void winpe_parse_manifest_resource_table(CLR_METADATA* clrh, char* buffer, char* ptr, UNSIGNED32 index_size, UNSIGNED32 row_size)
{
    UNSIGNED32 resource_offset, string_index_size, name_offset, name_length, implementation_index;
    UNSIGNED32 i;
    char *tmp;

    /* we only care about the seal resource */
    memset(&clrh->seal_resource, 0, sizeof(clrh->seal_resource));
    for (i = 0; i < clrh->rows_per_table[TBL_MANIFESTRESOURCE]; i++)
    {
        if (ptr + row_size > buffer + clrh->clrh.MetaData.Size)
            break; /* overflow */

        resource_offset = UNSIGNED32_from_little_endian(ptr);
        if (resource_offset < clrh->file_size)
        {
            string_index_size = (clrh->flags & 1 ? 4 : 2);
            if (index_size == 4)
                implementation_index = UNSIGNED32_from_little_endian(ptr + 4 + 4 + string_index_size);
            else
                implementation_index = UNSIGNED16_from_little_endian(ptr + 4 + 4 + string_index_size);
            if (implementation_index == 0)
            {
                /* internal resource */
                if (string_index_size == 4)
                    name_offset = UNSIGNED32_from_little_endian(ptr + 4 + 4); /* + offset + flags */
                else
                    name_offset = UNSIGNED16_from_little_endian(ptr + 4 + 4); /* + offset + flags */
                if (clrh->string_stream.offset + name_offset < clrh->clrh.MetaData.Size)
                {
                    name_length = 0;
                    tmp = buffer + name_offset;
                    for (; *tmp; ++tmp, ++name_length)
                    {
                        if (tmp >= buffer + clrh->clrh.MetaData.Size)
                        {
                            name_length = 0;
                            break;
                        }
                    }
                    if (name_length && name_length > 12 && 0 == strncmp(buffer + name_offset + name_length - 12, ".AESEAL.json", 12)) /* 12 is strlen(".AESEAL.json") */
                    {
                        clrh->seal_resource.offset = clrh->resources_offset + resource_offset;
                        if (clrh->seal_resource.offset + 4 < clrh->file_size)
                            break; /* no interest in other resources */
                    }
                }
            }
        }
        ptr += row_size;
    }
}

int winpe_is_correct_clr_file(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, CLR_METADATA* clrh)
{
    char *buffer, *ptr = NULL, *tmp;
    int i, j, err = 1;
    UNSIGNED16 metadata_streams = 0;
    CLR_METADATA_STREAM stream;
    UNSIGNED32 string_index_size = 0, guid_index_size = 0, blob_index_size = 0;
    UNSIGNED32 index_size1, index_size2, row_size;

    if (winpe_read_clr20_header(pCtx, fp, peh, clrh))
    {
        if (!pCtx->FileSeekCallBack(fp, clrh->metadata_offset, SEEK_SET))
        {
            /* read metadata */
            buffer = (char*)memory_alloc(clrh->clrh.MetaData.Size);
            if (buffer)
            {
                if (pCtx->FileReadCallBack(fp, buffer, clrh->clrh.MetaData.Size) == clrh->clrh.MetaData.Size)
                {
                    memset(clrh->rows_per_table, 0, sizeof(clrh->rows_per_table));
                    memset(&clrh->metadata_stream, 0, sizeof(clrh->metadata_stream));
                    memset(&clrh->string_stream, 0, sizeof(clrh->string_stream));
                    memset(&clrh->blob_stream, 0, sizeof(clrh->blob_stream));

                    /* parse metadata */
                    if (4 + 2 + 2 + 4 + 4 + 2 + 2 <= clrh->clrh.MetaData.Size) /* signature + major version + minor version + reserved + length + flags + streams */
                    {
                        ptr = buffer;
                        if (UNSIGNED32_from_little_endian(ptr) == 0x424A5342)
                        {
                            ptr += sizeof(UNSIGNED32) + sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + sizeof(UNSIGNED32);
                            if (4 + 2 + 2 + 4 + 4 + 2 + 2 + UNSIGNED32_from_little_endian(ptr) <= clrh->clrh.MetaData.Size)
                            {
                                ptr += UNSIGNED32_from_little_endian(ptr) + sizeof(UNSIGNED32);
                                if ((UNSIGNED64)ptr % 4)
                                    ptr += 4 - (UNSIGNED64)ptr % 4; /* align */
                                ptr += sizeof(UNSIGNED16);
                                metadata_streams = UNSIGNED16_from_little_endian(ptr);
                                ptr += sizeof(UNSIGNED16);
                                err = 0;
                            }
                        }
                    }

                    /* Parse streams */
                    if (!err)
                    {
                        for (i = 0; i < metadata_streams && !err; i++)
                        {
                            if (ptr + 4 + 4 > buffer + clrh->clrh.MetaData.Size)
                            {
                                err = 1;
                                continue;
                            }
                            stream.offset = UNSIGNED32_from_little_endian(ptr); /* relative to the start of the MetaData section */
                            ptr += sizeof(UNSIGNED32);
                            stream.size = UNSIGNED32_from_little_endian(ptr);
                            ptr += sizeof(UNSIGNED32);
                            if (ptr >= buffer + clrh->clrh.MetaData.Size)
                            {
                                err = 1;
                                continue;
                            }
                            j = 0;
                            for (; *ptr; ++ptr, ++j)
                            {
                                if (ptr >= buffer + clrh->clrh.MetaData.Size)
                                {
                                    err = 1;
                                    continue;
                                }
                            }
                            if (0 == strncmp(ptr - j, "#~", j))
                            {
                                clrh->metadata_stream = stream;
                            }
                            else if (0 == strncmp(ptr - j, "#-", j))
                            {
                                clrh->metadata_stream = stream;
                            }
                            else if (0 == strncmp(ptr - j, "#Strings", j))
                            {
                                clrh->string_stream = stream;
                            }
                            else if (0 == strncmp(ptr - j, "#Blob", j))
                            {
                                clrh->blob_stream = stream;
                            }
                            ptr++; /* null terminator */
                            if ((UNSIGNED64)ptr % 4)
                                ptr += 4 - (UNSIGNED64)ptr % 4; /* align */
                        }
                        if (!err && (clrh->metadata_stream.offset == 0 || clrh->string_stream.offset == 0 || clrh->blob_stream.offset == 0))
                        {
                            err = 1;
                        }
                    }

                    /* Parse metadata table (stream #~ or #-) */
                    if (!err)
                    {
                        err = 1;
                        if (4 + 1 + 1 + 1 + 1 + 8 + 8 <= clrh->metadata_stream.size) /* reserved + major version + minor version + heap_offset_sizes + reserved + valid_tables + sorted_tables */
                        {
                            ptr = buffer;
                            ptr += sizeof(UNSIGNED32) + sizeof(UNSIGNED8) + sizeof(UNSIGNED8);
                            clrh->flags = *(UNSIGNED8*)ptr;
                            string_index_size = (clrh->flags & 1 ? 4 : 2);
                            guid_index_size = (clrh->flags & 2 ? 4 : 2);
                            blob_index_size = (clrh->flags & 4 ? 4 : 2);
                            ptr += sizeof(UNSIGNED8) + sizeof(UNSIGNED8);
                            clrh->valid_tables = UNSIGNED64_from_little_endian(ptr);
                            ptr += sizeof(UNSIGNED64) + sizeof(UNSIGNED64);
                            if (ptr + 4 * clrh->valid_tables <= buffer + clrh->metadata_stream.size) /* rows per valid tables */
                            {
                                for (i = 0; i < 64; i++)
                                {
                                    if (clrh->valid_tables & ((UNSIGNED64)1 << i))
                                    {
                                        clrh->rows_per_table[i] = UNSIGNED32_from_little_endian(ptr);
                                        ptr += sizeof(UNSIGNED32);
                                    }
                                }
                                if (clrh->flags & 0x40)
                                {
                                    /* There is extra data after the row count */
                                    ptr += sizeof(UNSIGNED32);
                                }
                                err = 0;
                            }
                        }
                    }

                    /* Parse the tables. Since the row size is dynamic we need to parse
                    all tables before any needed one. So parse them all. */
                    for (i = 0; i < 64 && !err; i++)
                    {
                        /* Skip not present tables */
                        if (!(clrh->valid_tables & (((UNSIGNED64)1) << i)))
                            continue;
                        if (ptr > buffer + clrh->metadata_stream.size)
                        {
                            err = 1;
                        }
                        switch (i)
                        {
                        case TBL_MODULE:
                            row_size = 2 + string_index_size + 3 * guid_index_size;
                            if (ptr + row_size > buffer + clrh->metadata_stream.size)
                            {
                                err = 1; /* overflow */
                            }
                            else
                            {
                                if (string_index_size == 4)
                                    clrh->module_name.offset = UNSIGNED32_from_little_endian(ptr + 2);
                                else
                                    clrh->module_name.offset = UNSIGNED16_from_little_endian(ptr + 2);
                                clrh->module_name.offset += clrh->string_stream.offset;
                                clrh->module_name.length = 0;
                                tmp = ptr;
                                for (; *tmp; ++tmp, ++clrh->module_name.length)
                                {
                                    if (tmp >= buffer + clrh->metadata_stream.size)
                                    {
                                        err = 1; /* overflow */
                                        break;
                                    }
                                }
                            }
                            ptr += row_size * clrh->rows_per_table[i];
                            break;
                        case TBL_TYPEREF:
                            clrh->typeref_table.dynamic_index_size = winpe_metadata_table_index_size(clrh, 2, TBL_MODULE, TBL_MODULEREF, TBL_ASSEMBLYREF, TBL_TYPEREF);
                            clrh->typeref_table.offset = (UNSIGNED32)(ptr - buffer - clrh->metadata_offset);
                            clrh->typeref_table.row_size = clrh->typeref_table.dynamic_index_size + 2 * string_index_size;
                            ptr += clrh->typeref_table.row_size * clrh->rows_per_table[i];
                            break;
                        case TBL_TYPEDEF:
                            ptr += (4 + 2 * string_index_size + winpe_metadata_table_index_size(clrh, 2, TBL_TYPEDEF, TBL_TYPEREF, TBL_TYPESPEC) + (clrh->rows_per_table[TBL_FIELD] > 0xFFFF ? 4 : 2) + (clrh->rows_per_table[TBL_METHODDEF] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_FIELDPTR:
                            ptr += (clrh->rows_per_table[TBL_FIELD] > 0xFFFF ? 4 : 2) * clrh->rows_per_table[i];
                            break;
                        case TBL_FIELD:
                            ptr += (2 + string_index_size + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_METHODDEFPTR:
                            ptr += (clrh->rows_per_table[TBL_METHODDEF] > 0xFFFF ? 4 : 2) * clrh->rows_per_table[i];
                            break;
                        case TBL_METHODDEF:
                            ptr += (4 + 2 + 2 + string_index_size + blob_index_size + (clrh->rows_per_table[TBL_PARAM] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_PARAMPTR:
                            ptr += clrh->rows_per_table[TBL_PARAM] * clrh->rows_per_table[i];
                            break;
                        case TBL_PARAM:
                            ptr += (2 + 2 + string_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_INTERFACEIMPL:
                            ptr += ((clrh->rows_per_table[TBL_TYPEDEF] > 0xFFFF ? 4 : 2) + winpe_metadata_table_index_size(clrh, 2, TBL_TYPEDEF, TBL_TYPEREF, TBL_TYPESPEC)) * clrh->rows_per_table[i];
                            break;
                        case TBL_MEMBERREF:
                            clrh->memberref_table.dynamic_index_size = winpe_metadata_table_index_size(clrh, 3, TBL_METHODDEF, TBL_MODULEREF, TBL_TYPEREF, TBL_TYPESPEC);
                            clrh->memberref_table.offset = (UNSIGNED32)(ptr - buffer - clrh->metadata_offset);
                            clrh->memberref_table.row_size = clrh->memberref_table.dynamic_index_size + string_index_size + blob_index_size;
                            ptr += clrh->memberref_table.row_size * clrh->rows_per_table[i];
                            break;
                        case TBL_CONSTANT:
                            ptr += (1 + 1 + winpe_metadata_table_index_size(clrh, 2, TBL_PARAM, TBL_FIELD, TBL_PROPERTY) + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_CUSTOMATTRIBUTE:
                            index_size1 = winpe_metadata_table_index_size(clrh, 5,
                                TBL_METHODDEF, TBL_FIELD, TBL_TYPEREF, TBL_TYPEDEF, TBL_PARAM, TBL_INTERFACEIMPL, TBL_MEMBERREF, TBL_MODULE,
                                TBL_PROPERTY, TBL_EVENT, TBL_STANDALONESIG, TBL_MODULEREF, TBL_TYPESPEC, TBL_ASSEMBLY, TBL_ASSEMBLYREF,
                                TBL_FILE, TBL_EXPORTEDTYPE, TBL_MANIFESTRESOURCE, TBL_GENERICPARAM, TBL_GENERICPARAMCONSTRAINT, TBL_METHODSPEC);
                            index_size2 = winpe_metadata_table_index_size(clrh, 3, TBL_METHODDEF, TBL_MEMBERREF);
                            row_size = index_size1 + index_size2 + blob_index_size;
                            winpe_parse_custom_attribute_table(clrh, buffer, ptr, index_size1, index_size2, row_size);
                            ptr += row_size * clrh->rows_per_table[i];
                            break;
                        case TBL_FIELDMARSHAL:
                            ptr += (winpe_metadata_table_index_size(clrh, 1, TBL_FIELD, TBL_PARAM) + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_DECLSECURITY:
                            ptr += (2 + winpe_metadata_table_index_size(clrh, 2, TBL_TYPEDEF, TBL_METHODDEF, TBL_ASSEMBLY) + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_CLASSLAYOUT:
                            ptr += (2 + 4 + (clrh->rows_per_table[TBL_TYPEDEF] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_FIELDLAYOUT:
                            ptr += (4 + (clrh->rows_per_table[TBL_FIELD] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_STANDALONESIG:
                            ptr += blob_index_size * clrh->rows_per_table[i];
                            break;
                        case TBL_EVENTMAP:
                            ptr += ((clrh->rows_per_table[TBL_TYPEDEF] > 0xFFFF ? 4 : 2) + clrh->rows_per_table[TBL_EVENT]) * clrh->rows_per_table[i];
                            break;
                        case TBL_EVENTPTR:
                            ptr += (clrh->rows_per_table[TBL_EVENT] > 0xFFFF ? 4 : 2) * clrh->rows_per_table[i];
                            break;
                        case TBL_EVENT:
                            ptr += (2 + string_index_size + winpe_metadata_table_index_size(clrh, 2, TBL_TYPEDEF, TBL_TYPEREF, TBL_TYPESPEC)) * clrh->rows_per_table[i];
                            break;
                        case TBL_PROPERTYMAP:
                            ptr += ((clrh->rows_per_table[TBL_TYPEDEF] > 0xFFFF ? 4 : 2) + (clrh->rows_per_table[TBL_PROPERTY] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_PROPERTYPTR:
                            ptr += (clrh->rows_per_table[TBL_PROPERTY] > 0xFFFF ? 4 : 2) * clrh->rows_per_table[i];
                            break;
                        case TBL_PROPERTY:
                            ptr += (2 + string_index_size + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_METHODSEMANTICS:
                            ptr += (2 + (clrh->rows_per_table[TBL_METHODDEF] > 0xFFFF ? 4 : 2) + winpe_metadata_table_index_size(clrh, 1, TBL_EVENT, TBL_PROPERTY)) * clrh->rows_per_table[i];
                            break;
                        case TBL_METHODIMPL:
                            ptr += ((clrh->rows_per_table[TBL_TYPEDEF] > 0xFFFF ? 4 : 2) + 2 * winpe_metadata_table_index_size(clrh, 1, TBL_METHODDEF, TBL_MEMBERREF)) * clrh->rows_per_table[i];
                            break;
                        case TBL_MODULEREF:
                            ptr += string_index_size * clrh->rows_per_table[i];
                            break;
                        case TBL_TYPESPEC:
                            ptr += blob_index_size * clrh->rows_per_table[i];
                            break;
                        case TBL_IMPLMAP:
                            ptr += (2 + winpe_metadata_table_index_size(clrh, 1, TBL_FIELD, TBL_METHODDEF) + string_index_size + (clrh->rows_per_table[TBL_MODULEREF] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_FIELDRVA:
                            ptr += (4 + (clrh->rows_per_table[TBL_FIELD] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_ENCLOG:
                            ptr += (4 + 4) * clrh->rows_per_table[i];
                            break;
                        case TBL_ENCMAP:
                            ptr += 4 * clrh->rows_per_table[i];
                            break;
                        case TBL_ASSEMBLY:
                            ptr += (4 + 2 + 2 + 2 + 2 + 4 + blob_index_size + 2 * string_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_ASSEMBLYPROCESSOR:
                            ptr += 4 * clrh->rows_per_table[i];
                            break;
                        case TBL_ASSEMBLYOS:
                            ptr += (4 + 4 + 4) * clrh->rows_per_table[i];
                            break;
                        case TBL_ASSEMBLYREF:
                            ptr += (2 + 2 + 2 + 2 + 4 + 2 * blob_index_size + 2 * string_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_ASSEMBLYREFPROCESSOR:
                            ptr += (4 + (clrh->rows_per_table[TBL_ASSEMBLYREFPROCESSOR] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_ASSEMBLYREFOS:
                            ptr += (4 + 4 + 4 + (clrh->rows_per_table[TBL_ASSEMBLYREF] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_FILE:
                            ptr += (4 + string_index_size + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_EXPORTEDTYPE:
                            ptr += (4 + 4 + 2 * string_index_size + winpe_metadata_table_index_size(clrh, 2, TBL_FILE, TBL_ASSEMBLYREF, TBL_EXPORTEDTYPE)) * clrh->rows_per_table[i];
                            break;
                        case TBL_MANIFESTRESOURCE:
                            index_size1 = winpe_metadata_table_index_size(clrh, 2, TBL_FILE, TBL_ASSEMBLYREF);
                            row_size = 4 + 4 + string_index_size + index_size1;
                            winpe_parse_manifest_resource_table(clrh, buffer, ptr, index_size1, row_size);
                            ptr += row_size * clrh->rows_per_table[i];
                            break;
                        case TBL_NESTEDCLASS:
                            ptr += (2 * (clrh->rows_per_table[TBL_TYPEDEF] > 0xFFFF ? 4 : 2)) * clrh->rows_per_table[i];
                            break;
                        case TBL_GENERICPARAM:
                            ptr += (2 + 2 + winpe_metadata_table_index_size(clrh, 1, TBL_TYPEDEF, TBL_METHODDEF) + string_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_METHODSPEC:
                            ptr += (winpe_metadata_table_index_size(clrh, 1, TBL_METHODDEF, TBL_MEMBERREF) + blob_index_size) * clrh->rows_per_table[i];
                            break;
                        case TBL_GENERICPARAMCONSTRAINT:
                            ptr += ((clrh->rows_per_table[TBL_GENERICPARAM] > 0xFFFF ? 4 : 2) + winpe_metadata_table_index_size(clrh, 2, TBL_TYPEDEF, TBL_TYPEREF, TBL_TYPESPEC)) * clrh->rows_per_table[i];
                            break;
                        default:
                            err = 1; /* unknown table */
                        }
                    }
                }
                memory_free(buffer);
            }
        }
    }
    
    return err;
}

int winpe_section_raw_data(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, char* name, unsigned long* start, unsigned long* size)
{
    unsigned long filepos;
    int i;
    TAG_IMAGE_SECTION_HEADER fs;

    filepos = peh->dh.e_lfanew + sizeof(UNSIGNED32) + sizeof(TAG_IMAGE_FILE_HEADER) + peh->fh.SizeOfOptionalHeader;
    /* shift file pointer to the sections array */
    if (file_seek(pCtx, fp, filepos, SEEK_SET))
    {
        /* reading all sections and find rwa address */
        for (i = 0; i < peh->fh.NumberOfSections; i++)
        {
            /* read section from the file */
            if (winpe_read_section_header(pCtx, fp, &fs))
            {
                if (0 == strncmp((char*)fs.Name, name, 1 + get_min(7, (unsigned long)strlen(name))))
                {
                    /* section found */
                    *start = winpe_raw_section_offset(peh, &fs);
                    *size = winpe_raw_section_size(peh, &fs);
                    return 1;
                }
                filepos += sizeof(TAG_IMAGE_SECTION_HEADER);
                if (!file_seek(pCtx, fp, filepos, SEEK_SET))
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }
    }
    return 0;
}

int winpe_find_resource_version_directory(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 directory_offset, TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY* version_data_directory)
{
    int res = 0;
    TAG_IMAGE_RESOURCE_DIRECTORY directory;
    UNSIGNED64 entry_offset;
    UNSIGNED32 i;

    if (!pCtx->FileSeekCallBack(fp, directory_offset, SEEK_SET))
    {
        /* read resource directory */
        if (pCtx->FileReadCallBack(fp, &directory, sizeof(directory)) == sizeof(directory))
        {
            /* verify overflow */
            if ((unsigned short)(directory.NumberOfIdEntries + directory.NumberOfNamedEntries) >= directory.NumberOfIdEntries)
            {
                /* Get the directory entries. Named entries come first. */
                entry_offset = directory_offset + sizeof(TAG_IMAGE_RESOURCE_DIRECTORY);
                for (i = 0; i < ((UNSIGNED32)directory.NumberOfNamedEntries + directory.NumberOfIdEntries); ++i)
                {
                    if (pCtx->FileSeekCallBack(fp, entry_offset, SEEK_SET))
                    {
                        break;
                    }

                    /* read directory entry */
                    if (pCtx->FileReadCallBack(fp, version_data_directory, sizeof(TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY)) == sizeof(TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY))
                    {
                        if (version_data_directory->Of.Dt.DataIsDirectory)
                        {
                            if (version_data_directory->Nm.Id == 16) /* 16 is RT_VERSION */
                            {
                                res = 1;
                                break; /* found */
                            }
                            /* search in root only */
                            /*res = winpe_find_resource_version_directory(pCtx, fp, resources_offset + directory_entry.DUMMYUNIONNAME2.DUMMYSTRUCTNAME2.OffsetToDirectory, version_data_directory);
                            if (res)
                            {
                                break;
                            }*/
                        }
                    }

                    entry_offset += sizeof(TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY);
                }
            }
        }
    }

    return res;
}

int winpe_find_resource_version_data(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED64 resources_offset, UNSIGNED64 directory_offset, TAG_IMAGE_RESOURCE_DATA_ENTRY* version_data_entry)
{
    int res = 0;
    TAG_IMAGE_RESOURCE_DIRECTORY directory;
    TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY directory_entry;
    UNSIGNED64 entry_offset;
    UNSIGNED32 i;

    if (!pCtx->FileSeekCallBack(fp, directory_offset, SEEK_SET))
    {
        /* read resource directory */
        if (pCtx->FileReadCallBack(fp, &directory, sizeof(directory)) == sizeof(directory))
        {
            /* verify overflow */
            if ((unsigned short)(directory.NumberOfIdEntries + directory.NumberOfNamedEntries) >= directory.NumberOfIdEntries)
            {
                /* Get the directory entries. Named entries come first. */
                entry_offset = directory_offset + sizeof(TAG_IMAGE_RESOURCE_DIRECTORY);
                for (i = 0; i < ((UNSIGNED32)directory.NumberOfNamedEntries + directory.NumberOfIdEntries); ++i)
                {
                    if (pCtx->FileSeekCallBack(fp, entry_offset, SEEK_SET))
                    {
                        break;
                    }

                    /* read directory entry */
                    if (pCtx->FileReadCallBack(fp, &directory_entry, sizeof(directory_entry)) == sizeof(directory_entry))
                    {
                        if (directory_entry.Of.Dt.DataIsDirectory)
                        {
                            res = winpe_find_resource_version_data(pCtx, fp, peh, resources_offset, resources_offset + directory_entry.Of.Dt.OffsetToDirectory, version_data_entry);
                            if (res)
                            {
                                break; /* found */
                            }
                        }
                        else
                        {
                            if (!pCtx->FileSeekCallBack(fp, resources_offset + directory_entry.Of.OffsetToData, SEEK_SET))
                            {
                                /* read data entry */
                                if (pCtx->FileReadCallBack(fp, version_data_entry, sizeof(TAG_IMAGE_RESOURCE_DATA_ENTRY)) == sizeof(TAG_IMAGE_RESOURCE_DATA_ENTRY))
                                {
                                    res = 1;
                                    break;
                                }
                            }
                        }
                    }

                    entry_offset += sizeof(TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY);
                }
            }
        }
    }

    return res;
}

/* Returned sizes are in bytes, include the NULL terminator and may contain
   extra characters because of alignment. */
int winpe_get_resource_version_info(
    PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh,
    UNSIGNED64 *filename_offset, UNSIGNED16 *filename_length,
    UNSIGNED64 *vendor_offset, UNSIGNED16 *vendor_length,
    UNSIGNED64* version_offset, UNSIGNED16 *version_length)
{
    int res = 0;
    UNSIGNED32 resources_va, resources_size;
    UNSIGNED64 resources_offset, version_data_offset, stringfileinfo_offset, stringtable_offset, entry_offset;
    UNSIGNED16 version_data_length, stringfileinfo_length, stringtable_length, entry_length, value;
    TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY directory_entry;
    TAG_IMAGE_RESOURCE_DATA_ENTRY version_data_entry;
    char unicode_str[16*2 + 2]; /* 16 is the longest buffer needed, plus NULL terminator */

    *vendor_length = *version_length = *filename_length = 0;
    if (winpe_is_pe64(peh))
    {
        resources_va = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        resources_size = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    }
    else
    {
        resources_va = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        resources_size = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    }
    if (winpe_va_to_raw(pCtx, fp, peh, resources_va, &resources_offset) && !pCtx->FileSeekCallBack(fp, resources_offset, SEEK_SET))
    {
        if (winpe_find_resource_version_directory(pCtx, fp, resources_offset, &directory_entry))
        {
            if (winpe_find_resource_version_data(pCtx, fp, peh, resources_offset, resources_offset + directory_entry.Of.Dt.OffsetToDirectory, &version_data_entry))
            {
                if (winpe_va_to_raw(pCtx, fp, peh, version_data_entry.OffsetToData, &version_data_offset))
                {
                    /* at offset 0 from version_data_offset is the full
                        version info length */
                    if (!pCtx->FileSeekCallBack(fp, version_data_offset, SEEK_SET) && file_read_UNSIGNED16(pCtx, fp, &version_data_length))
                    {
                        /* at offset 6 from version_data_offset there must
                        be the UNICODE string "VS_VERSION_INFO" */
                        if (!pCtx->FileSeekCallBack(fp, version_data_offset + 6, SEEK_SET))
                        {
                            /* VS_VERSION_INFO is always little endian */
                            if (pCtx->FileReadCallBack(fp, &unicode_str, 16*sizeof(UNSIGNED16)) == 16*sizeof(UNSIGNED16)) /* 16 is strlen("VS_VERSION_INFO") + NULL terminator */
                            {
                                if (0 == memcmp(unicode_str, "V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0", 16 * sizeof(UNSIGNED16)))
                                {
                                    stringfileinfo_offset = version_data_offset + 3*sizeof(UNSIGNED16) + 16*sizeof(UNSIGNED16) + sizeof(TAG_VS_FIXEDFILEINFO);
                                    /* align */
                                    stringfileinfo_offset += 3;
                                    stringfileinfo_offset &= 0xfffffffc;
                                    while (!pCtx->FileSeekCallBack(fp, stringfileinfo_offset, SEEK_SET) && file_read_UNSIGNED16(pCtx, fp, &stringfileinfo_length) && stringfileinfo_length)
                                    {
                                        if (!pCtx->FileSeekCallBack(fp, stringfileinfo_offset + 3*sizeof(UNSIGNED16), SEEK_SET))
                                        {
                                            /* StringFileInfo is always little endian */
                                            if (pCtx->FileReadCallBack(fp, &unicode_str, 15*sizeof(UNSIGNED16)) == 15*sizeof(UNSIGNED16)) /* 15 is strlen("StringFileInfo") + NULL terminator */
                                            {
                                                if (0 == memcmp(unicode_str, "S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0", 15*sizeof(UNSIGNED16))) /* 15 is strlen("StringFileInfo") + NULL terminator */
                                                {
                                                    stringtable_offset = stringfileinfo_offset + 3*sizeof(UNSIGNED16) + 15*sizeof(UNSIGNED16);
                                                    /* align */
                                                    stringtable_offset += 3;
                                                    stringtable_offset &= 0xfffffffc;
                                                    while (!pCtx->FileSeekCallBack(fp, stringtable_offset, SEEK_SET) && file_read_UNSIGNED16(pCtx, fp, &stringtable_length) && stringtable_length && stringtable_offset < stringfileinfo_offset + stringfileinfo_length)
                                                    {
                                                        if (!pCtx->FileSeekCallBack(fp, stringtable_offset + 3*sizeof(UNSIGNED16), SEEK_SET))
                                                        {
                                                            entry_offset = stringtable_offset + 3*sizeof(UNSIGNED16);
                                                            /* Skip the name */
                                                            while (file_read_UNSIGNED16(pCtx, fp, &value) && value)
                                                            {
                                                                entry_offset += sizeof(UNSIGNED16);
                                                            }
                                                            entry_offset += sizeof(UNSIGNED16); /* NULL terminator*/
                                                            /* align */
                                                            entry_offset += 3;
                                                            entry_offset &= 0xfffffffc;
                                                            while (!pCtx->FileSeekCallBack(fp, entry_offset, SEEK_SET) && file_read_UNSIGNED16(pCtx, fp, &entry_length) && entry_length && entry_offset < stringtable_offset + stringtable_length)
                                                            {
                                                                if (!pCtx->FileSeekCallBack(fp, entry_offset + 3*sizeof(UNSIGNED16), SEEK_SET))
                                                                {
                                                                    /* We are interested in CompanyName, ProductVersion
                                                                        and OriginalFilename. The maximum length is 17. */
                                                                    if (pCtx->FileReadCallBack(fp, &unicode_str, 17*sizeof(UNSIGNED16)) == 17*sizeof(UNSIGNED16))
                                                                    {
                                                                        if (0 == memcmp(unicode_str, "C\0o\0m\0p\0a\0n\0y\0N\0a\0m\0e\0\0\0", 12*sizeof(UNSIGNED16))) /* 12 is strlen("CompanyName") + NULL terminator */
                                                                        {
                                                                            *vendor_offset = entry_offset + 3*sizeof(UNSIGNED16) + 12*sizeof(UNSIGNED16);
                                                                            *vendor_offset += 2; /* align */
                                                                            *vendor_length = entry_length - (3*sizeof(UNSIGNED16) + 12*sizeof(UNSIGNED16) + 2);
                                                                        }
                                                                        else if (0 == memcmp(unicode_str, "P\0r\0o\0d\0u\0c\0t\0V\0e\0r\0s\0i\0o\0n\0\0\0", 15*sizeof(UNSIGNED16))) /* 15 is strlen("ProductVersion") + NULL terminator */
                                                                        {
                                                                            *version_offset = entry_offset + 3*sizeof(UNSIGNED16) + 15*sizeof(UNSIGNED16); /* already aligned */
                                                                            *version_length = entry_length - (3*sizeof(UNSIGNED16) + 15*sizeof(UNSIGNED16));
                                                                        }
                                                                        else if (0 == memcmp(unicode_str, "O\0r\0i\0g\0i\0n\0a\0l\0F\0i\0l\0e\0n\0a\0m\0e\0\0\0", 17*sizeof(UNSIGNED16))) /* 17 is strlen("OriginalFilename") + NULL terminator */
                                                                        {
                                                                            *filename_offset = entry_offset + 3*sizeof(UNSIGNED16) + 17*sizeof(UNSIGNED16); /* already aligned */
                                                                            *filename_length = entry_length - (3*sizeof(UNSIGNED16) + 17*sizeof(UNSIGNED16));
                                                                        }
                                                                    }

                                                                    /* Increment */
                                                                    entry_offset += entry_length;
                                                                    /* align */
                                                                    entry_offset += 3;
                                                                    entry_offset &= 0xfffffffc;
                                                                }
                                                            }
                                                            if (*vendor_length && *version_length && *filename_length)
                                                            {
                                                                res = 1;
                                                            }
                                                        }
 
                                                        if (res)
                                                        {
                                                            break;
                                                        }

                                                        /* Increment */
                                                        stringtable_offset += stringtable_length;
                                                        /* align */
                                                        stringtable_offset += 3;
                                                        stringtable_offset &= 0xfffffffc;
                                                    };
                                                }
                                            }
                                        }

                                        if (res)
                                        {
                                            break;
                                        }

                                        /* Increment */
                                        stringfileinfo_offset += stringfileinfo_length;
                                        /* align */
                                        stringfileinfo_offset += 3;
                                        stringfileinfo_offset &= 0xfffffffc;
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return res;
}

#endif
