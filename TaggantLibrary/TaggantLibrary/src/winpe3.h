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


#ifndef WINPE3_HEADER
#define WINPE3_HEADER

#include "types.h"
#include "taggant_types.h"

#pragma pack(push,1)

typedef struct _TAG_IMAGE_RESOURCE_DIRECTORY {
    UNSIGNED8 Reserved[12];
    /* Uncomment necessary values
    UNSIGNED32   Characteristics;
    UNSIGNED32   TimeDateStamp;
    UNSIGNED16   MajorVersion;
    UNSIGNED16   MinorVersion;
    */
    UNSIGNED16   NumberOfNamedEntries;
    UNSIGNED16   NumberOfIdEntries;
    //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} TAG_IMAGE_RESOURCE_DIRECTORY, *PTAG_IMAGE_RESOURCE_DIRECTORY;

typedef struct _TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            UNSIGNED32 NameOffset : 31;
            UNSIGNED32 NameIsString : 1;
        } No;
        UNSIGNED32   Name;
        UNSIGNED16   Id;
    } Nm;
    union {
        UNSIGNED32   OffsetToData;
        struct {
            UNSIGNED32   OffsetToDirectory : 31;
            UNSIGNED32   DataIsDirectory : 1;
        } Dt;
    } Of;
} TAG_IMAGE_RESOURCE_DIRECTORY_ENTRY, *PTAG_IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _TAG_IMAGE_RESOURCE_DATA_ENTRY {
    UNSIGNED32   OffsetToData;
    UNSIGNED32   Size;
    UNSIGNED8    Reserved[8];
    /* Uncomment necessary values
    UNSIGNED32   CodePage;
    UNSIGNED32   Reserved;
    */
} TAG_IMAGE_RESOURCE_DATA_ENTRY, *PTAG_IMAGE_RESOURCE_DATA_ENTRY;

typedef struct _TAG_VS_FIXEDFILEINFO {
    UNSIGNED32 dwSignature;
    UNSIGNED32 dwStrucVersion;
    UNSIGNED32 dwFileVersionMS;
    UNSIGNED32 dwFileVersionLS;
    UNSIGNED32 dwProductVersionMS;
    UNSIGNED32 dwProductVersionLS;
    UNSIGNED32 dwFileFlagsMask;
    UNSIGNED32 dwFileFlags;
    UNSIGNED32 dwFileOS;
    UNSIGNED32 dwFileType;
    UNSIGNED32 dwFileSubtype;
    UNSIGNED32 dwFileDateMS;
    UNSIGNED32 dwFileDateLS;
} TAG_VS_FIXEDFILEINFO, *PTAG_VS_FIXEDFILEINFO;

// CLR 2.0 header structure.
typedef struct _TAG_IMAGE_COR20_HEADER
{
    // Header versioning
    UNSIGNED8 Reserved1[8];
    /* Uncomment necessary values
    UNSIGNED32                  cb;
    UNSIGNED16                  MajorRuntimeVersion;
    UNSIGNED16                  MinorRuntimeVersion;
    */

    // Symbol table and startup information
    TAG_IMAGE_DATA_DIRECTORY    MetaData;
    UNSIGNED32                  Flags;

    // If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is not set, EntryPointToken represents a managed entrypoint.
    // If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set, EntryPointRVA represents an RVA to a native entrypoint.
    UNSIGNED8 Reserved2[4];
    /* Uncomment necessary values
    union {
    UNSIGNED32              EntryPointToken;
    UNSIGNED32              EntryPointRVA;
    } DUMMYUNIONNAME;
    */

    // Binding information
    TAG_IMAGE_DATA_DIRECTORY    Resources;
    UNSIGNED8 Reserved3[5 * sizeof(TAG_IMAGE_DATA_DIRECTORY)];
    /* Uncomment necessary values
    TAG_IMAGE_DATA_DIRECTORY    StrongNameSignature;

    // Regular fixup and binding information
    TAG_IMAGE_DATA_DIRECTORY    CodeManagerTable;
    TAG_IMAGE_DATA_DIRECTORY    VTableFixups;
    TAG_IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

    // Precompiled image info (internal use only - set to zero)
    TAG_IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
    */
} TAG_IMAGE_COR20_HEADER, *PTAG_IMAGE_COR20_HEADER;

#pragma pack(pop)

typedef struct _CLR_METADATA_STREAM {
    UNSIGNED32 offset;
    UNSIGNED32 size;
} CLR_METADATA_STREAM, *PCLR_METADATA_STREAM;

typedef struct _CLR_TABLE_INFO {
    UNSIGNED32 offset;
    UNSIGNED32 row_size;
    UNSIGNED32 dynamic_index_size;
} CLR_TABLE_INFO, *PCLR_TABLE_INFO;

typedef struct _CLR_STRING {
    UNSIGNED32 offset;
    UNSIGNED32 length;
} CLR_STRING, *PCLR_STRING;

typedef struct _CLR_INTERNAL_RESOURCE {
    UNSIGNED64 offset;
} CLR_INTERNAL_RESOURCE, *PCLR_INTERNAL_RESOURCE;

typedef struct _CLR_METADATA {
    TAG_IMAGE_COR20_HEADER clrh;
    UNSIGNED64 file_size;
    UNSIGNED64 cor20_offset;
    UNSIGNED32 cor20_size;
    UNSIGNED64 resources_offset;
    UNSIGNED64 metadata_offset;
    CLR_METADATA_STREAM metadata_stream;
    CLR_METADATA_STREAM string_stream;
    CLR_METADATA_STREAM blob_stream;
    UNSIGNED64 module_table_offset;
    UNSIGNED64 custom_attributetable_table_offset;
    UNSIGNED64 assembly_table_offset;
    UNSIGNED64 manifest_resource_table_offset;
    UNSIGNED8 flags;
    UNSIGNED64 valid_tables;
    UNSIGNED32 rows_per_table[64];
    CLR_TABLE_INFO typeref_table;
    CLR_TABLE_INFO memberref_table;
    CLR_STRING module_name;
    CLR_STRING company;
    CLR_INTERNAL_RESOURCE seal_resource;
    UNSIGNED16 major_version;
    UNSIGNED16 minor_version;
    UNSIGNED16 build_number;
    UNSIGNED16 revision_number;
} CLR_METADATA, *PCLR_METADATA;

 /* checks file header if the file is correct CLR file
 returns 1 is CLR data directory is valid */
int winpe_is_correct_clr_file(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, CLR_METADATA* clrh);

int winpe_section_raw_data(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, char* name, unsigned long* start, unsigned long* size);

int winpe_get_resource_version_info(
    PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh,
    UNSIGNED64 *filename_offset, UNSIGNED16 *filename_length,
    UNSIGNED64 *vendor_offset, UNSIGNED16 *vendor_length,
    UNSIGNED64* version_offset, UNSIGNED16 *version_length);

#endif /* WINPE3_HEADER */
