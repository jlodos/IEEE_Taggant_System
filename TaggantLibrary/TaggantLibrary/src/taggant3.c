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

 /*
 * Portions of this software include software developed by the OpenSSL Project for
 * use in the OpenSSL Toolkit (http://www.openssl.org/), and those portions
 * are governed by the OpenSSL Toolkit License.
 */

#include "global.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "types.h"
#include "winpe.h"
#include "winpe2.h"
#include "winpe3.h"
#include "taggant.h"
#include "taggant2.h"
#include "taggant3.h"
#include "callbacks.h"
#include "endianness.h"
#include "miscellaneous.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/asn1.h>

#if defined(SSV_SEAL_LIBRARY) || defined(SPV_SEAL_LIBRARY)
#include <cJSON.c>
#endif

#ifdef SSV_SEAL_LIBRARY

/* From openssl/src/crypto/o_time.h */
int OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec);

/* From openssl/src/crypto/asn1/a_gentm.c */
int taggant3_asn1_generalizedtime_to_tm(struct tm *tm, ASN1_GENERALIZEDTIME *d)
{
    static int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
    static int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    if (d->type != V_ASN1_GENERALIZEDTIME)
        return (0);
    l = d->length;
    a = (char *)d->data;
    o = 0;
    /*
    * GENERALIZEDTIME is similar to UTCTIME except the year is represented
    * as YYYY. This stuff treats everything as a two digit field so make
    * first two fields 00 to 99
    */
    if (l < 13)
        goto err;
    for (i = 0; i < 7; i++) {
        if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n * 100 - 1900;
                break;
            case 1:
                tm->tm_year += n;
                break;
            case 2:
                tm->tm_mon = n - 1;
                break;
            case 3:
                tm->tm_mday = n;
                break;
            case 4:
                tm->tm_hour = n;
                break;
            case 5:
                tm->tm_min = n;
                break;
            case 6:
                tm->tm_sec = n;
                break;
            }
        }
    }
    /*
    * Optional fractional seconds: decimal point followed by one or more
    * digits.
    */
    if (a[o] == '.') {
        if (++o > l)
            goto err;
        i = o;
        while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
            o++;
        /* Must have at least one digit after decimal point */
        if (i == o)
            goto err;
    }

    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '-' ? -1 : 1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 7; i < 9; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 7)
                    offset = n * 3600;
                else if (i == 8)
                    offset += n * 60;
            }
            o++;
        }
        if (offset && !OPENSSL_gmtime_adj(tm, 0, offset * offsign))
            return 0;
    }
    else if (a[o]) {
        /* Missing time zone information. */
        goto err;
    }
    return (o == l);
err:
    return (0);
}

UNSIGNED64 taggant3_ctime_from_struct_tm(struct tm* t)
{
    UNSIGNED64 year_for_leap;
    UNSIGNED64 month = t->tm_mon % 12;
    UNSIGNED64 year = t->tm_year + t->tm_mon / 12;
    static int month_day[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

    /* Convert to time_t */
    if (month < 0)
    {
        month += 12;
        --year;
    }
    year_for_leap = (month > 1) ? year + 1 : year; /* number of Februaries since 1900 */

    return t->tm_sec                                   /* seconds */
             + 60 * (t->tm_min                         /* minutes */
             + 60 * (t->tm_hour                        /* hours */
             + 24 * (month_day[month] + t->tm_mday - 1 /* days */
             + 365 * (year - 70)                       /* years */
             + (year_for_leap - 69) / 4                /* plus leap years */
             - (year_for_leap - 1) / 100               /* minus centuries (mostly not leap years) */
             + (year_for_leap + 299) / 400)));         /* plus 400s (leap years) */
}

UNSIGNED64 taggant3_ctime_from_iso8601_time(char* start, char* end)
{
    /* t is something like "2016-11-20T19:12:14.505Z" or "2016-11-20T19:12:14.505-5:00".
       Seconds may be missing. */
    UNSIGNED64 res = 0;
    struct tm tm_res = { 0 };
    float sec;
    int tzh = 0, tzm = 0, tokens;
    char* t = (char*)memory_alloc(end - start + 1);
    if (t)
    {
        strncpy(t, start, end - start);
        t[end - start] = 0;
        tokens = sscanf(t, "%d-%d-%dT%d:%d:%f%d:%dZ", &tm_res.tm_year, &tm_res.tm_mon, &tm_res.tm_mday, &tm_res.tm_hour, &tm_res.tm_min, &sec, &tzh, &tzm);
        if (5 <= tokens)
        {
            if (6 < tokens && tzh < 0)
                tzm = -tzm; /* fix the sign on minutes */
            tm_res.tm_year -= 1900;
            tm_res.tm_mon -= 1;
            if (6 <= tokens)
                tm_res.tm_sec = (int)sec;
            res = taggant3_ctime_from_struct_tm(&tm_res);
        }
        memory_free(t);
    }
    return res;
}

PKCS7* taggant3_get_pe_file_signature(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh)
{
    UNSIGNED32 ds_offset, ds_size, cert_offset, cert_size;
    unsigned char *cert_data;
    BIO *cert_bio;
    PKCS7 *cert_pkcs7, *app_pkcs7 = NULL;
    int er;

    /* get the signature, maybe a dual signature */
    if (winpe_is_pe64(peh))
    {
        ds_offset = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        ds_size = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }
    else
    {
        ds_offset = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        ds_size = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }
    if (ds_offset != 0 && ds_size != 0)
    {
        cert_offset = ds_offset;
        app_pkcs7 = cert_pkcs7 = NULL;
        er = 0;
        while (!er && file_seek(pCtx, fp, cert_offset, SEEK_SET) && file_read_UNSIGNED32(pCtx, fp, &cert_size) && cert_offset + cert_size <= peh->filesize)
        {
            er = 1;
            if (cert_size > 8)
            {
                cert_size -= 8;
                cert_data = (unsigned char*)memory_alloc(cert_size);
                if (cert_data)
                {
                    if (file_seek(pCtx, fp, cert_offset + 8, SEEK_SET) && file_read_buffer(pCtx, fp, cert_data, cert_size))
                    {
                        cert_bio = BIO_new_mem_buf(cert_data, cert_size);
                        if (cert_bio)
                        {
                            cert_pkcs7 = d2i_PKCS7_bio(cert_bio, NULL);
                            if (cert_pkcs7)
                            {
                                PKCS7_free(app_pkcs7);
                                app_pkcs7 = cert_pkcs7; /* save current version */
                                er = 0;
                            }
                            BIO_free(cert_bio);
                        }
                    }
                    memory_free(cert_data);
                }
                cert_offset += cert_size;
                /* align */
                cert_offset += 7;
                cert_offset &= 0xfffffff8;
            }
        }
    }

    return app_pkcs7;
}

UNSIGNED32 taggant3_get_pe_seal_info(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, CLR_METADATA* clrh, char* str_hash)
{
    UNSIGNED32 res = TNOTFOUND;
    char *json_seal = NULL;
    unsigned long json_start = 0, json_size = 0;
    cJSON_Hooks hooks;
    cJSON *root, *signed_seal;
    char *signed_seal_buf = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    int i;

    /* get the seal */
    if (winpe_section_raw_data(pCtx, fp, peh, ".AESeal", &json_start, &json_size))
    {
        /* try from section first */
        json_seal = (char*)memory_alloc(json_size + 1);
        if (json_seal)
        {
            if (!file_seek(pCtx, fp, json_start, SEEK_SET) || !file_read_buffer(pCtx, fp, json_seal, json_size))
            {
                memory_free(json_seal);
                json_seal = NULL;
                json_size = 0;
            }
            else
            {
                json_seal[json_size] = 0;
            }
        }
    }
    if (!json_seal)
    {
        /* try from CLR resource */
        if (clrh->cor20_offset || winpe_is_correct_clr_file(pCtx, fp, peh, clrh))
        {
            if (file_seek(pCtx, fp, clrh->seal_resource.offset, SEEK_SET) && file_read_buffer(pCtx, fp, &json_size, 4))
            {
                if (IS_BIG_ENDIAN)
                {
                    json_size = UNSIGNED32_to_big_endian((char*)&json_size);
                }
                json_seal = (char*)memory_alloc(json_size + 1);
                if (json_seal)
                {
                    if (!file_seek(pCtx, fp, clrh->seal_resource.offset + 4, SEEK_SET) || !file_read_buffer(pCtx, fp, json_seal, json_size))
                    {
                        memory_free(json_seal);
                        json_seal = NULL;
                        json_size = 0;
                    }
                    else
                    {
                        json_seal[json_size] = 0;
                    }
                }
            }
        }
    }

    /* get seal info */
    str_hash[0] = 0;
    str_hash[2 * SHA256_DIGEST_LENGTH] = 0;
    if (json_seal)
    {
        /* init memory functions */
        hooks.malloc_fn = memory_alloc;
        hooks.free_fn = memory_free;
        cJSON_InitHooks(&hooks);

        /* parse JSON*/
        root = cJSON_Parse(json_seal);
        signed_seal = cJSON_GetObjectItem(root, "signedSeal");

        /**********************************************************************************/
        /* patch for SRCL C++ native apps */
        if (!signed_seal)
        {
            /* calculate hash */
            signed_seal_buf = json_seal;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, signed_seal_buf, strlen(signed_seal_buf));
            SHA256_Final(hash, &sha256);
            for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                sprintf(str_hash + 2 * i, "%02x", hash[i]);
            }
            res = TNOERR;
        }
        /**********************************************************************************/

        if (signed_seal)
        {
            /* calculate hash */
            signed_seal_buf = signed_seal->valuestring;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, signed_seal_buf, strlen(signed_seal_buf));
            SHA256_Final(hash, &sha256);
            for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                sprintf(str_hash + 2 * i, "%02x", hash[i]);
            }
            res = TNOERR;
        }
        memory_free(json_seal);
    }

    return res;
}

/* if successful the caller must release output data */
UNSIGNED32 taggant3_get_pe_file_info(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, CLR_METADATA* clrh, PKCS7 *app_pkcs7, char **app_version, char **app_vendor, char **app_filename, char** app_cert_thumbprints, size_t* app_certs)
{
    UNSIGNED32 res = TNOTFOUND;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    UNSIGNED64 filename_offset, vendor_offset, version_offset;
    UNSIGNED16 filename_length, vendor_length, version_length, i;
    STACK_OF(X509) *certs;
    X509 *cert;
    UNSIGNED16 MAX_UNSIGNED16_STR_LENGTH = 12; /* 2 * (strlen(65535) plus NULL terminator) */
    UNSIGNED16* utf16_start;
    UNSIGNED8* utf8_start;

    /* initialize output */   
    *app_certs = 0;
    *app_version = *app_vendor = *app_filename = *app_cert_thumbprints = NULL;

    filename_length = vendor_length = version_length = 0;
    if (!winpe_get_resource_version_info(pCtx, fp, peh, &filename_offset, &filename_length, &vendor_offset, &vendor_length, &version_offset, &version_length))
    {
        if (clrh->cor20_offset || winpe_is_correct_clr_file(pCtx, fp, peh, clrh))
        {
            filename_offset = clrh->module_name.offset;
            filename_length = (unsigned short)clrh->module_name.length;
            vendor_offset = clrh->company.offset;
            vendor_length = (unsigned short)clrh->company.length;
            version_offset = 0;
            version_length = clrh->major_version;
        }
    }

    if (filename_length && vendor_length && version_length)
    {
        if (version_offset == 0 && version_length)
        {
            /* CLR version */
            *app_version = (char*)memory_alloc(MAX_UNSIGNED16_STR_LENGTH * 2); /* leave space for conversion to string and to UTF8 */
        }
        else
        {
            /* Win32 version*/
            *app_version = (char*)memory_alloc(version_length * 2); /* x2 to leave space for UTF16 to UTF8 conversion */
        }
        *app_vendor = (char*)memory_alloc(vendor_length * 2); /* x2 to leave space for UTF16 to UTF8 conversion */
        *app_filename = (char*)memory_alloc(filename_length * 2); /* x2 to leave space for UTF16 to UTF8 conversion */
        if (*app_version && *app_vendor && *app_filename)
        {
            if (file_seek(pCtx, fp, filename_offset, SEEK_SET) && file_read_buffer(pCtx, fp, *app_filename, filename_length))
            {
                if (file_seek(pCtx, fp, vendor_offset, SEEK_SET) && file_read_buffer(pCtx, fp, *app_vendor, vendor_length))
                {
                    if (version_offset == 0 && version_length)
                    {
                        /* CLR version */
                        memset(*app_version, 0, MAX_UNSIGNED16_STR_LENGTH * 2);
                        sprintf(*app_version, "%d", version_length); /* the major version was stored in version_length */
                        version_length = MAX_UNSIGNED16_STR_LENGTH;
                        for (i = 5; i > 0; i--) /* convert to UNICODE little endian */
                        {
                            (*app_version)[2 * i] = *app_version[i];
                            (*app_version)[i] = 0;
                        }
                    }
                    else
                    {
                        /* Win32 version*/
                        if (file_seek(pCtx, fp, version_offset, SEEK_SET) && file_read_buffer(pCtx, fp, *app_version, version_length))
                        {
                            /* get major version, no leading spaces allowed */
                            for (i = 0; i < version_length; i += 2) /* always little endian */
                            {
                                if ((*app_version)[i] == '.' || (*app_version)[i] == ',' || (*app_version)[i] == ' ')
                                {
                                    (*app_version)[i] = 0;
                                    version_length = i + 2; /* adjust length, including NULL terminator */
                                    break;
                                }
                            }
                        }
                        else
                        {
                            **app_version = 0;
                        }
                    }
                    if (**app_version)
                    {
                        /* Succeeded getting PE data, now convert to UTF8 */
                        memcpy(*app_version + version_length, *app_version, version_length); /* Copy to the second half of the buffer to reuse it */
                        utf16_start = (UNSIGNED16*)(*app_version + version_length);
                        utf8_start = (UNSIGNED8*)*app_version;
                        if (convert_utf16_to_utf8(&utf16_start, &utf8_start, utf8_start + 2 * version_length))
                        {
                            memcpy(*app_vendor + vendor_length, *app_vendor, vendor_length); /* Copy to the second half of the buffer to reuse it */
                            utf16_start = (UNSIGNED16*)(*app_vendor + vendor_length);
                            utf8_start = (UNSIGNED8*)*app_vendor;
                            if (convert_utf16_to_utf8(&utf16_start, &utf8_start, utf8_start + 2 * vendor_length))
                            {
                                memcpy(*app_filename + filename_length, *app_filename, filename_length); /* Copy to the second half of the buffer to reuse it */
                                utf16_start = (UNSIGNED16*)(*app_filename + filename_length);
                                utf8_start = (UNSIGNED8*)*app_filename;
                                if (convert_utf16_to_utf8(&utf16_start, &utf8_start, utf8_start + 2 * filename_length))
                                {
                                    certs = PKCS7_get0_signers(app_pkcs7, NULL, 0);
                                    if (certs)
                                    {
                                        for (i = 0; i < sk_X509_num(certs); i++)
                                        {
                                            cert = sk_X509_value(certs, i);
                                            if (X509_digest(cert, EVP_sha1(), hash, NULL))
                                            {
                                                // the thumbprint is in hash
                                                *app_cert_thumbprints = (char*)memory_realloc(*app_cert_thumbprints, (*app_certs + 1) * 2 * SHA_DIGEST_LENGTH + 1); /* plus NULL terminator */
                                                if (*app_cert_thumbprints)
                                                {
                                                    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
                                                    {
                                                        sprintf(*app_cert_thumbprints + *app_certs * 2 * SHA_DIGEST_LENGTH + 2 * i, "%02x", hash[i]);
                                                    }
                                                    (*app_certs)++;
                                                }
                                                else
                                                {
                                                    *app_certs = 0;
                                                    break; /* low memory, there is nothing we can do to recover */
                                                }
                                            }
                                        }
                                        sk_X509_free(certs);
                                    }
                                    if (app_certs)
                                    {
                                        res = TNOERR;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (res != TNOERR)
        {
            /* low memory or invalid PE */
            memory_free(*app_version);
            memory_free(*app_vendor);
            memory_free(*app_filename);
            memory_free(*app_cert_thumbprints);
            *app_version = *app_vendor = *app_filename = *app_cert_thumbprints = NULL;
        }
    }

    return res;
}

UNSIGNED64 taggant3_get_pe_file_signature_timestamp(PKCS7 *app_pkcs7)
{
    UNSIGNED64 res = 0;
    struct tm tm_res;
    PKCS7 *ts_pkcs7;
    STACK_OF(PKCS7_SIGNER_INFO) *signer_infos;
    PKCS7_SIGNER_INFO *signer_info;
    X509_ATTRIBUTE *x509_attr;
    ASN1_OBJECT *asn1_obj;
    ASN1_TYPE *asn1_type = NULL;
    BIO *bio;
    X509_STORE *store;
    unsigned char *tmp_data;
    UNSIGNED8 *tst_data;
    int tst_size, i;
    TS_TST_INFO *tst_info;

    UNSIGNED8 SPC_RFC3161_OBJID[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01 }; /* 1.3.6.1.4.1.311.3.3.1 */

    signer_infos = PKCS7_get_signer_info(app_pkcs7);
    if (signer_infos && sk_PKCS7_SIGNER_INFO_num(signer_infos) == 1)
    {
        signer_info = sk_PKCS7_SIGNER_INFO_value(signer_infos, 0);
        if (signer_info && signer_info->unauth_attr)
        {
            /* the RFC3161 timestamp is an unauthenticated attribute */
            for (i = 0; i < sk_X509_ATTRIBUTE_num(signer_info->unauth_attr) && res == 0; i++)
            {
                /* Search RFC3161 timestamp with SPC_RFC3161_OBJID */
                x509_attr = sk_X509_ATTRIBUTE_value(signer_info->unauth_attr, i);
                if (x509_attr)
                {
                    asn1_obj = X509_ATTRIBUTE_get0_object(x509_attr);
                    if (asn1_obj)
                    {
                        if (asn1_obj->length == sizeof(SPC_RFC3161_OBJID) && 0 == memcmp(asn1_obj->data, SPC_RFC3161_OBJID, sizeof(SPC_RFC3161_OBJID)))
                        {
                            asn1_type = X509_ATTRIBUTE_get0_type(x509_attr, 0);
                            if (asn1_type)
                            {
                                if (asn1_type->value.octet_string->data && asn1_type->value.octet_string->length)
                                {
                                    tmp_data = asn1_type->value.octet_string->data;
                                    ts_pkcs7 = d2i_PKCS7(NULL, &tmp_data, asn1_type->value.octet_string->length);
                                    if (ts_pkcs7)
                                    {
                                        if (PKCS7_type_is_signed(ts_pkcs7))
                                        {
                                            store = X509_STORE_new();
                                            if (store)
                                            {
                                                bio = BIO_new(BIO_s_mem());
                                                if (bio)
                                                {
                                                    /* We do not validate the chain because the containing certificate
                                                    thumbprint was already validated */
                                                    if (PKCS7_verify(ts_pkcs7, NULL, store, NULL, bio, PKCS7_NOVERIFY))
                                                    {
                                                        tst_data = (UNSIGNED8*)memory_alloc(2048); /* 20148 should be enough for a TS_TST_INFO */
                                                        if (tst_data)
                                                        {
                                                            /* Build TS_TST_INFO structure from the signed ts_pkcs7 content */
                                                            tst_size = BIO_read(bio, (void *)tst_data, 2048);
                                                            tmp_data = tst_data;
                                                            tst_info = d2i_TS_TST_INFO(NULL, &tmp_data, tst_size);
                                                            if (tst_info)
                                                            {
                                                                /* if (ASN1_TIME_to_tm(TstInfo->time, &tm_res)) works with newer openssl versions.
                                                                   If used taggant3_asn1_generalizedtime_to_tm and the openssl notice may be  removed. */
                                                                if (taggant3_asn1_generalizedtime_to_tm(&tm_res, tst_info->time))
                                                                {
                                                                    res = taggant3_ctime_from_struct_tm(&tm_res);
                                                                }
                                                                TS_TST_INFO_free(tst_info);
                                                            }
                                                            memory_free(tst_data);
                                                        }
                                                    }
                                                    BIO_free(bio);
                                                }
                                                X509_STORE_free(store);
                                            }
                                        }
                                        PKCS7_free(ts_pkcs7);
                                    }
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

UNSIGNED32 taggant3_validate_pe_file_signature(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, PKCS7 *app_pkcs7)
{
    UNSIGNED32 res = TMISMATCH;
    UNSIGNED8 *spc_indirect_data;
    UNSIGNED16 spc_indirect_data_size;
    EVP_MD_CTX evp;
    STACK_OF(X509_ALGOR) *md_algs;
    X509_ALGOR *md_alg;
    BIO *bio;
    X509_STORE *store;
    HASHBLOB_DEFAULT hash_blob;
    UNSIGNED8 SPC_INDIRECT_DATA_OBJID[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04 }; /* OID 1.3.6.1.4.1.311.2.1.4 */
    UNSIGNED32 ds_size, hash_size = 0;

    if (PKCS7_type_is_signed(app_pkcs7) && app_pkcs7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE)
    {
        if (0 == memcmp(app_pkcs7->d.sign->contents->type->data, SPC_INDIRECT_DATA_OBJID, sizeof(SPC_INDIRECT_DATA_OBJID)))
        {
            /* Parse ASN.1 data */
            spc_indirect_data = (UNSIGNED8*)(app_pkcs7->d.sign->contents->d.other->value.asn1_string->data);
            spc_indirect_data_size = 0;
            if ((spc_indirect_data[1] & 0x80) == 0)
            {
                spc_indirect_data_size = spc_indirect_data[1] & 0x7F; /* 1 byte length encoding */
                spc_indirect_data += 2;
            }
            else if ((spc_indirect_data[1] & 0x82) == 0x82)
            {
                spc_indirect_data_size = ((UNSIGNED16)spc_indirect_data[2] << 8) + spc_indirect_data[3]; /* 2 bytes length encoding */
                spc_indirect_data += 4;
            }
            if (spc_indirect_data_size)
            {
                /* Compute PE hash */
                EVP_MD_CTX_init(&evp);
                md_algs = app_pkcs7->d.sign->md_algs;
                md_alg = sk_X509_ALGOR_value(md_algs, 0);
                switch (OBJ_obj2nid(md_alg->algorithm))
                {
                case NID_sha1:
                    EVP_DigestInit_ex(&evp, EVP_sha1(), NULL);
                    hash_size = 20;
                    break;
                case NID_sha224:
                    EVP_DigestInit_ex(&evp, EVP_sha224(), NULL);
                    hash_size = 28;
                    break;
                case NID_sha256:
                    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
                    hash_size = 32;
                    break;
                }
                if (winpe_is_pe64(peh))
                {
                    ds_size = (UNSIGNED32)peh->oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                }
                else
                {
                    ds_size = (UNSIGNED32)peh->oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                }
                if (hash_size && TNOERR == taggant2_compute_default_hash_pe(&evp, pCtx, &hash_blob, fp, peh, peh->filesize - ds_size))
                {
                    /* compare hashes */
                    if (0 == memcmp(spc_indirect_data + spc_indirect_data_size - hash_size, hash_blob.Header.Hash, hash_size))
                    {
                        /* verify PKCS7 data */
                        bio = BIO_new_mem_buf(spc_indirect_data, spc_indirect_data_size);
                        if (bio)
                        {
                            store = X509_STORE_new();
                            if (store)
                            {
                                if (PKCS7_verify(app_pkcs7, app_pkcs7->d.sign->cert, store, bio, NULL, PKCS7_NOVERIFY))
                                {
                                    /* We do not verify the certificate chain. At this point 
                                       we know the signing certificate is valid because its 
                                       thumbprint matched that included in the signed taggant.
                                       Since the hashes match, even if some certificate in the
                                       chain is forged, the file content is the one signed with
                                       an approved certificate. */
                                    res = TNOERR;
                                }
                                X509_STORE_free(store);
                            }
                            BIO_free(bio);
                        }
                    }
                }
                EVP_MD_CTX_cleanup(&evp);
            }
        }
    }

    return res;
}

UNSIGNED32 taggant3_validate_pe_file_info(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED32 uInfoSize, PINFO pInfo)
{
    UNSIGNED32 res = TMISMATCH;
    PKCS7 *app_pkcs7;
    CLR_METADATA clrh;
    char str_hash[2 * SHA256_DIGEST_LENGTH + 1];
    char *app_version, *app_vendor, *app_filename, *app_cert_thumbprints;
    size_t app_certs;
    char *seal_hash_in_taggant, *seal_hash_in_taggant_end;
    char *valid_from_in_taggant, *valid_from_in_taggant_end;
    char *valid_to_in_taggant, *valid_to_in_taggant_end;
    char *filename_in_taggant, *filename_in_taggant_end;
    char *vendor_in_taggant, *vendor_in_taggant_end;
    char *version_in_taggant, *version_in_taggant_end;
    char *thumbprint_in_taggant, *thumbprint_in_taggant_end = NULL;
    size_t i;
    UNSIGNED64 signing_time, seal_from_time, seal_to_time;

    /* get the signature, maybe a dual signature */
    app_pkcs7 = taggant3_get_pe_file_signature(pCtx, fp, peh);
    if (app_pkcs7)
    {
        /* get seal info */
        memset(&clrh, 0, sizeof(clrh));
        if (TNOERR == taggant3_get_pe_seal_info(pCtx, fp, peh, &clrh, str_hash))
        {
            /* get PE info */
            if (TNOERR == taggant3_get_pe_file_info(pCtx, fp, peh, &clrh, app_pkcs7, &app_version, &app_vendor, &app_filename, &app_cert_thumbprints, &app_certs))
            {
                /* parse taggant info */
                seal_hash_in_taggant = pInfo;
                seal_hash_in_taggant_end = (char*)memchr(seal_hash_in_taggant, '\x1', pInfo + uInfoSize - seal_hash_in_taggant);
                if (seal_hash_in_taggant_end)
                {
                    valid_from_in_taggant = seal_hash_in_taggant_end + 1;
                    valid_from_in_taggant_end = (char*)memchr(valid_from_in_taggant, '\x1', pInfo + uInfoSize - valid_from_in_taggant);
                    if (valid_from_in_taggant_end)
                    {
                        valid_to_in_taggant = valid_from_in_taggant_end + 1;
                        valid_to_in_taggant_end = (char*)memchr(valid_to_in_taggant, '\x1', pInfo + uInfoSize - valid_to_in_taggant);
                        if (valid_to_in_taggant_end)
                        {
                            filename_in_taggant = valid_to_in_taggant_end + 1;
                            filename_in_taggant_end = (char*)memchr(filename_in_taggant, '\x1', pInfo + uInfoSize - filename_in_taggant);
                            while (filename_in_taggant_end && res != TNOERR)
                            {
                                vendor_in_taggant = filename_in_taggant_end + 1;
                                vendor_in_taggant_end = (char*)memchr(vendor_in_taggant, '\x1', pInfo + uInfoSize - vendor_in_taggant);
                                if (vendor_in_taggant_end)
                                {
                                    version_in_taggant = vendor_in_taggant_end + 1;
                                    version_in_taggant_end = (char*)memchr(version_in_taggant, '\x1', pInfo + uInfoSize - version_in_taggant);
                                    if (version_in_taggant_end)
                                    {
                                        thumbprint_in_taggant = version_in_taggant_end + 1;
                                        thumbprint_in_taggant_end = (char*)memchr(thumbprint_in_taggant, '\x1', pInfo + uInfoSize - thumbprint_in_taggant);
                                        if (thumbprint_in_taggant_end && 2 * SHA_DIGEST_LENGTH == thumbprint_in_taggant_end - thumbprint_in_taggant)
                                        {
                                            /* match taggant info against seal and PE info */
                                            if (
#ifdef _WIN32
                                                _strnicmp(seal_hash_in_taggant, str_hash, seal_hash_in_taggant_end - seal_hash_in_taggant) == 0 &&
                                                _strnicmp(filename_in_taggant, app_filename, filename_in_taggant_end - filename_in_taggant) == 0 &&
                                                _strnicmp(vendor_in_taggant, app_vendor, vendor_in_taggant_end - vendor_in_taggant) == 0 &&
#else
                                                strncasecmp(seal_hash_in_taggant, str_hash, seal_hash_in_taggant_end - seal_hash_in_taggant) == 0 &&
                                                strncasecmp(filename_in_taggant, app_filename, filename_in_taggant_end - filename_in_taggant) == 0 &&
                                                strncasecmp(vendor_in_taggant, app_vendor, vendor_in_taggant_end - vendor_in_taggant) == 0 &&
#endif
                                                strncmp(version_in_taggant, app_version, version_in_taggant_end - version_in_taggant) == 0
                                                )
                                            {
                                                for (i = 0; i < app_certs; i++)
                                                {
#ifdef _WIN32
                                                    if (_strnicmp(thumbprint_in_taggant, app_cert_thumbprints + i * 2 * SHA_DIGEST_LENGTH, 2 * SHA_DIGEST_LENGTH) == 0)
#else
                                                    if (strncasecmp(thumbprint_in_taggant, app_cert_thumbprints + i * 2 * SHA_DIGEST_LENGTH, 2 * SHA_DIGEST_LENGTH) == 0)
#endif
                                                    {
                                                        /* validate PE digital signature */
                                                        res = taggant3_validate_pe_file_signature(pCtx, fp, peh, app_pkcs7);
                                                        if (TNOERR == res)
                                                        {
                                                            /* verify signing date */
                                                            signing_time = taggant3_get_pe_file_signature_timestamp(app_pkcs7);
                                                            if (signing_time == 0)
                                                            {
                                                                // could not get the timestamp
                                                            }
                                                            else
                                                            {
                                                                seal_from_time = taggant3_ctime_from_iso8601_time(valid_from_in_taggant, valid_from_in_taggant_end);
                                                                seal_to_time = taggant3_ctime_from_iso8601_time(valid_to_in_taggant, valid_to_in_taggant_end);
                                                                if (seal_from_time && seal_from_time <= signing_time && signing_time <= seal_to_time)
                                                                {
                                                                    res = TNOERR;
                                                                }
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                            if (pInfo + uInfoSize <= filename_in_taggant)
                                            {
                                                /* no more entries */
                                                break;
                                            }
                                            filename_in_taggant = thumbprint_in_taggant_end + 1;
                                            filename_in_taggant_end = (char*)memchr(filename_in_taggant, '\x1', pInfo + uInfoSize - filename_in_taggant);
                                        }
                                        else
                                        {
                                            /* invalid taggant */
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                memory_free(app_version);
                memory_free(app_vendor);
                memory_free(app_filename);
                memory_free(app_cert_thumbprints);
            }
        }

        PKCS7_free(app_pkcs7);
    }

    return res;
}

UNSIGNED32 taggant3_validate_default_hashes_pe(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT fp)
{
    UNSIGNED32 res = TMISMATCH;
    unsigned int infosize = 0;
    char* info = NULL;
    PE_ALL_HEADERS peh;

    if (winpe_is_correct_pe_file(pCtx, fp, &peh))
    {
        /* validate PE info */
        res = taggant2_get_info(pTaggantObj, ESEALINFO, &infosize, NULL);
        if (res == TINSUFFICIENTBUFFER)
        {
            // Allocate enough buffer
            info = (char*)memory_alloc(infosize);
            if (info)
            {
                res = taggant2_get_info(pTaggantObj, ESEALINFO, &infosize, info);
                if (res == TNOERR)
                {
                    res = taggant3_validate_pe_file_info(pCtx, fp, &peh, infosize, info);
                }
                memory_free(info);
            }
        }
    }
    else
    {
        res = TINVALIDPEFILE;
    }

    return res;
}

#endif

#ifdef SPV_SEAL_LIBRARY

UNSIGNED32 taggant3_validate_seal_signature(unsigned char* json, unsigned int jsonlen, char* signature, char* cert)
{
    UNSIGNED32 res = TBADKEY;
    unsigned char *certder, *signatureder;
    char *certsubject;
    int certlen, signaturelen;
    BIO *bio;
    X509 *x509cert;
    EVP_PKEY *evp_pubkey;
    RSA *rsa_pubkey;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    signatureder = (unsigned char*)memory_alloc(strlen(signature));
    if (signatureder)
    {
        certder = (unsigned char*)memory_alloc(strlen(cert));
        if (certder)
        {
            bio = BIO_new_mem_buf(cert, -1);
            if (bio)
            {
                bio = BIO_push(BIO_new(BIO_f_base64()), bio);
                BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
                certlen = BIO_read(bio, certder, (int)strlen(cert));
                BIO_free_all(bio);
                bio = BIO_new_mem_buf(signature, -1);
                if (bio)
                {
                    bio = BIO_push(BIO_new(BIO_f_base64()), bio);
                    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
                    signaturelen = BIO_read(bio, signatureder, (int)strlen(signature));
                    BIO_free_all(bio);
                    bio = BIO_new_mem_buf((void*)certder, certlen);
                    if (bio)
                    {
                        x509cert = d2i_X509_bio(bio, NULL);
                        if (x509cert)
                        {
                            certsubject = X509_NAME_oneline(X509_get_subject_name(x509cert), NULL, 0);
//todo: validate a certificate root instead of "AppEsteem"?
                            if (strstr(certsubject, "AppEsteem"))
                            {
//todo: validate certificate chain

                                evp_pubkey = X509_get_pubkey(x509cert);
                                if (evp_pubkey)
                                {
                                    rsa_pubkey = EVP_PKEY_get1_RSA(evp_pubkey);
                                    if (rsa_pubkey)
                                    {
                                        SHA256_Init(&sha256);
                                        SHA256_Update(&sha256, json, jsonlen);
                                        SHA256_Final(hash, &sha256);
                                        if (1 == RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signatureder, signaturelen, rsa_pubkey))
                                        {
                                            res = TNOERR;
                                        }
                                        RSA_free(rsa_pubkey);
                                    }
                                    EVP_PKEY_free(evp_pubkey);
                                }
                                X509_free(x509cert);
                            }
                            OPENSSL_free(certsubject);
                        }
                        BIO_free(bio);
                    }
                }
            }
            memory_free(certder);
        }
        memory_free(signatureder);
    }

    return res;
}

/* If the return value is not NULL the caller must release it with memory_free() */
PINFO taggant3_get_seal_info_from_buffer(char *fullsealbuf)
{
    PINFO res = NULL;
    size_t resultsize;
    UNSIGNED32 fileentries = 0;
    char *signedsealbuf = NULL, *signaturebuf = NULL, *x509certificatebuf = NULL, *sealbuf = NULL, *endsealbuf = NULL;
    cJSON_Hooks hooks;
    cJSON *root, *signedseal;
    cJSON *seal_root, *seal, *validdates, *validfrom, *validto, *content, *files, *file, *name, *vendor, *version, *thumbprint;
    cJSON *header, *signature, *x509certificate;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    unsigned int i, er = 0;

    /* init memory functions */
    hooks.malloc_fn = memory_alloc;
    hooks.free_fn = memory_free;
    cJSON_InitHooks(&hooks);

    /* parse JSON */
    root = cJSON_Parse(fullsealbuf);
    signedseal = cJSON_GetObjectItem(root, "signedSeal");
    if (signedseal)
    {
        signedsealbuf = signedseal->valuestring;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, signedsealbuf, strlen(signedsealbuf));
        SHA256_Final(hash, &sha256);
    }
    seal_root = cJSON_Parse(signedsealbuf);
    header = cJSON_GetObjectItem(seal_root, "header");
    seal = cJSON_GetObjectItem(seal_root, "seal");
    signature = cJSON_GetObjectItem(header, "signature");
    x509certificate = cJSON_GetObjectItem(header, "x509Cert");
    if (signature)
    {
        signaturebuf = signature->valuestring;
    }
    if (x509certificate)
    {
        x509certificatebuf = x509certificate->valuestring;
    }
    if (signedsealbuf)
    {
        sealbuf = strstr(signedsealbuf, "seal");
        if (sealbuf)
        {
            sealbuf = strchr(sealbuf + 4 + 1, '{'); /* 4 is strlen("seal") +1 because of the colon */
            if (sealbuf)
            {
                endsealbuf = strrchr(sealbuf, '}');
                if (!endsealbuf)
                {
                    sealbuf = NULL;
                }
            }
        }
    }
    if (signaturebuf && x509certificatebuf && sealbuf)
    {
        if (TNOERR == taggant3_validate_seal_signature((unsigned char*)sealbuf, (unsigned int)(endsealbuf - sealbuf), signaturebuf, x509certificatebuf))
        {
            validdates = cJSON_GetObjectItem(seal, "validDates");
            validfrom = cJSON_GetObjectItem(validdates, "validForFilesSignedAfter");
            validto = cJSON_GetObjectItem(validdates, "validForFilesSignedBefore");
            if (validfrom && validto)
            {
                content = cJSON_GetObjectItem(seal, "contents");
                files = cJSON_GetObjectItem(content, "files");
                if (files)
                {
                    /* calculate size */
                    fileentries = cJSON_GetArraySize(files);
                    resultsize = 0;
                    if (!er)
                    {
                        resultsize += 2 * SHA256_DIGEST_LENGTH + 1 +  // + separator
                            strlen(validfrom->valuestring) + 1 +
                            strlen(validto->valuestring) + 1;
                    }
                    for (i = 0; i < fileentries && !er; i++)
                    {
                        file = cJSON_GetArrayItem(files, i);
                        name = cJSON_GetObjectItem(file, "name");
                        vendor = cJSON_GetObjectItem(file, "vendor");
                        version = cJSON_GetObjectItem(file, "majorVersion");
                        thumbprint = cJSON_GetObjectItem(file, "thumbprint");
                        if (!name || !vendor || !version || !thumbprint)
                        {
                            er = 1;
                        }
                        else
                        {
                            resultsize += strlen(name->valuestring) + 1 + // + separator
                                strlen(vendor->valuestring) + 1 +
                                strlen(version->valuestring) + 1 +
                                strlen(thumbprint->valuestring) + 1;
                        }
                    }
                    resultsize++; /* null terminator*/
                    if (!er)
                    {
                        /* set result */
                        res = (PINFO)memory_alloc(resultsize);
                        if (res)
                        {
                            res[resultsize - 1] = 0;
                            *res = 0;
                            for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
                            {
                                sprintf(res + (2 * i), "%02x", hash[i]);
                            }
                            strcat(res, "\x1");
                            strcat(res, validfrom->valuestring);
                            strcat(res, "\x1");
                            strcat(res, validto->valuestring);
                            strcat(res, "\x1");
                            for (i = 0; i < fileentries; i++)
                            {
                                file = cJSON_GetArrayItem(files, i);
                                name = cJSON_GetObjectItem(file, "name");
                                vendor = cJSON_GetObjectItem(file, "vendor");
                                version = cJSON_GetObjectItem(file, "majorVersion");
                                thumbprint = cJSON_GetObjectItem(file, "thumbprint");
                                strcat(res, name->valuestring);
                                strcat(res, "\x1");
                                strcat(res, vendor->valuestring);
                                strcat(res, "\x1");
                                strcat(res, version->valuestring);
                                strcat(res, "\x1");
                                strcat(res, thumbprint->valuestring);
                                strcat(res, "\x1");
                            }
                        }
                    }
                }
            }
        }
    }

    /* cleanup */
    cJSON_Delete(seal_root);
    cJSON_Delete(root);

    return res;
}

/* If the return value is not NULL the caller must release it with memory_free() */
PINFO taggant3_get_seal_info(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp)
{
	PINFO res = NULL;
	UNSIGNED64 filesize;
	char *fullsealbuf;

	/* read the JSON file */
	filesize = get_file_size(pCtx, fp);
	if (filesize)
	{
		fullsealbuf = (char*)memory_alloc((size_t)filesize);
		if (fullsealbuf)
		{
			if (file_seek(pCtx, fp, 0, SEEK_SET) && file_read_buffer(pCtx, fp, fullsealbuf, (size_t)filesize))
			{
				res = taggant3_get_seal_info_from_buffer(fullsealbuf);
			}
			memory_free(fullsealbuf);
		}
	}

	return res;
}

#endif
