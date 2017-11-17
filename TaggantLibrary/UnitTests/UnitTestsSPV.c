// UnitTestsSPV.cpp : Defines the entry point for the console application.
//

#include <taggantlib.h>
#include <taggant3.h>
#include <stdio.h>
#include <string.h>

#define SIGNTOOL_VERSION 0x030000

char tsurl[] = "http://taggant-tsa.ieee.org/";

char license[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIFdjCCA16gAwIBAgIQCITGFWNxNygKMWFJQeBMMzANBgkqhkiG9w0BAQsFADB5\n"
	"MQswCQYDVQQGEwJVUzFEMEIGA1UEChM7VGhlIEluc3RpdHV0ZSBvZiBFbGVjdHJp\n"
	"Y2FsIGFuZCBFbGVjdHJvbmljcyBFbmdpbmVlcnMsIEluYy4xDTALBgNVBAsTBElF\n"
	"RUUxFTATBgNVBAMTDElFRUUgUm9vdCBDQTAeFw0xNzA4MDEwMDAwMDBaFw0zNzA3\n"
	"MzEyMzU5NTlaMGYxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVBcHBFc3RlZW0gQ29y\n"
	"cG9yYXRpb24xEjAQBgNVBAsTCUFwcEVzdGVlbTEjMCEGA1UEAxMaQXBwRXN0ZWVt\n"
	"IENlcnRpZmljYXRpb24gQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n"
	"AQDg5/Ta3gcDaUw5QQC7eoQwK5QEo5JCEaT5HTPyY86RiJ+v5+9mgWeT8nIvLKHf\n"
	"8KwCPgSpHCMRt2ue2W947Ctf3eLf8JrJverHKNO+D4TwPz6j2EzHmjqKDu/dh4Ix\n"
	"KSRaspqxMIJbDL1eFp+uwKv27rBn4l7Kfazf94Cyv45ZDaCnf65W81oWZH5ulBsm\n"
	"q4UxQ7mXgkf8mor/d1u5qXpuTsVNqBvMn2w6Z6zv/qeMrfC2MEsquFZaEbESuocv\n"
	"wK0DpfNlFb4u7E6Y2jw7abt+jj0lnE96tlBc/Ir7XwCk/RJxA6soN1ezqo1v/ofS\n"
	"jBf1OaFRUCCl1MwkclzKdMyDAgMBAAGjggELMIIBBzASBgNVHRMBAf8ECDAGAQH/\n"
	"AgEAMHYGA1UdHwRvMG0wa6BpoGeGZWh0dHA6Ly9wa2ktY3JsLnN5bWF1dGguY29t\n"
	"L29mZmxpbmVjYS9UaGVJbnN0aXR1dGVvZkVsZWN0cmljYWxhbmRFbGVjdHJvbmlj\n"
	"c0VuZ2luZWVyc0luY0lFRUVSb290Q0EuY3JsMA4GA1UdDwEB/wQEAwIBBjApBgNV\n"
	"HREEIjAgpB4wHDEaMBgGA1UEAxMRU3ltYW50ZWNQS0ktMi03ODYwHQYDVR0OBBYE\n"
	"FEjnyTpQY7G5lwwH6j1sl2UkpMSsMB8GA1UdIwQYMBaAFLl7z+ulQgZEX6VC5OL0\n"
	"944itM5PMA0GCSqGSIb3DQEBCwUAA4ICAQBwIFS4pwtU60SCm2f0sVDfB3e8mad4\n"
	"16/3U+1u6CFxZTPRnSOIMrEHnkN3Vn8aRRhQqsr1aFuZOLxotBmv1whXl8lROXzx\n"
	"oOJRE7IKMW8pQi8YJJZJdFxVaF5irjNjPfZAZT44QEyEKdAKkAi+87G5Zt1ye2oT\n"
	"STV22PyUvCITdmW0F+pVdtFOiEOAc55kdVISPBG38Ufs+J+biV3hBDgpVsLMOtB8\n"
	"kG1J/tqRGOnQkIFdjvrjwQ07wmSFpf5TmxprLgv27ZjZPRNdfixIMkTlfmmaJ990\n"
	"+SuHKDzVOH5+R3h3Y1Z8KW6RHRr1roKKnRF9pVzyjxkbZ5N9TWPdT46gv1r3XB1j\n"
	"u1qD6zMF9KZucQE0hEwp84sZDjE3RT/7AuNz5bXL7Ugf3ulv2NzLq1H9E+/J9xSg\n"
	"TiFLyz0liqFS12MjqfkA585UvR5aJ0BqNOVwGTO8/VOCw6syxACGZxqJ6BcpJCMx\n"
	"MwQV3rbK+OU8ZyqE2ge7F19MWB2wnH1DJcoZqj5+BC7t32HCxWKOkQk3rfYASyod\n"
	"3adMVItAWA76jXwzpEyBLsJWF4cQgjkJv7fL4FB5sIJ5pjZXpnzp6h6s1FB8e8lF\n"
	"urkPylkArGaUuActFZ3SMbS715sC0gNhOjpL0Sj0LZM+cTpQs5kdehPFTAFHLM6b\n"
	"d6sisRqNb/SBCA==\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEGTCCAwGgAwIBAgIQVW0jYed0uJaGcPGsonc0QzANBgkqhkiG9w0BAQsFADBm\n"
	"MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVQXBwRXN0ZWVtIENvcnBvcmF0aW9uMRIw\n"
	"EAYDVQQLEwlBcHBFc3RlZW0xIzAhBgNVBAMTGkFwcEVzdGVlbSBDZXJ0aWZpY2F0\n"
	"aW9uIENBMB4XDTE3MDgwNTAwMDAwMFoXDTI3MDgwMzIzNTk1OVowOTEXMBUGA1UE\n"
	"AwwOVGVzdCBmb3IgSm9yZ2UxHjAcBgNVBAoMFUFwcEVzdGVlbSBDb3Jwb3JhdGlv\n"
	"bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKjrPOUJAjOYY4qX7VAS\n"
	"0kUqpavHNUdpSuZQwxKyfzlwXMRkvSpSDRLiJjtUiAm9/G7iskCnTrSPB0jfLLuU\n"
	"mlGsZe/0T/JJfm8LFP3gMoGFH2wSOAXCUAXWm1peMFqZi+vam1svV+PLg20QGxrl\n"
	"tYS5oxd9P/ppJuGktBNqAU7TXe2eKHttu8aYYm9l5WJ2BndUw9eHPTK4mJxFqwc2\n"
	"vc7ZCsS9MFLd9ABh++gnwQTIQfFwzE9wU+1y0/Tbjn+Oa5tw451r/PfZm3rw3fGF\n"
	"//qycv4kdrosojEk4LMiC+l+zqn3yPt+ofXgWO+ZsjFvR+OUyNclx4yPQgw3qPyg\n"
	"VncCAwEAAaOB7zCB7DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNV\n"
	"HSUEDDAKBggrBgEFBQcDAjBdBgNVHR8EVjBUMFKgUKBOhkxodHRwOi8vcGtpLWNy\n"
	"bC5zeW1hdXRoLmNvbS9jYV9iMTI3M2EyNTY1M2M4ZWFlYjc2ZWUyYmY5YjRjNTUz\n"
	"OC9MYXRlc3RDUkwuY3JsMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0\n"
	"cDovL3BraS1vY3NwLnN5bWF1dGguY29tMB8GA1UdIwQYMBaAFEjnyTpQY7G5lwwH\n"
	"6j1sl2UkpMSsMA0GCSqGSIb3DQEBCwUAA4IBAQBsQEVmmYiTgiA5OwDomiFDGQMx\n"
	"mrteoXvlHkvwKBkx6QL/Xk35ou53vUzZVR1xN4lLtWc/Ox9UpkKUXWjzjX5iUIQW\n"
	"yZqTfOIrtk98nd6tJu7COSdNt6cpym/vbVEB689cb0ZNNRH49zI0YPE8iwxD90Pd\n"
	"cW57odSDWmef7+3BRASqdYvmZejNGsgFcvMPKDR8uYUXaKvRpHplZwp1dbIHUatX\n"
	"v5UONVSTm27whJ/65cvCAm3t9AKFtxO3qhAIHmdi9IbTNTFgTM8c/sxeIOJJUVpt\n"
	"VVdd/qt/muOsHLWIJLjf2xUxlReD0Pi7GiewoeYN1i7stHpRSuSJ76XoEWZX\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIEowIBAAKCAQEAqOs85QkCM5hjipftUBLSRSqlq8c1R2lK5lDDErJ/OXBcxGS9\n"
	"KlINEuImO1SICb38buKyQKdOtI8HSN8su5SaUaxl7/RP8kl+bwsU/eAygYUfbBI4\n"
	"BcJQBdabWl4wWpmL69qbWy9X48uDbRAbGuW1hLmjF30/+mkm4aS0E2oBTtNd7Z4o\n"
	"e227xphib2XlYnYGd1TD14c9MriYnEWrBza9ztkKxL0wUt30AGH76CfBBMhB8XDM\n"
	"T3BT7XLT9NuOf45rm3DjnWv899mbevDd8YX/+rJy/iR2uiyiMSTgsyIL6X7OqffI\n"
	"+36h9eBY75myMW9H45TI1yXHjI9CDDeo/KBWdwIDAQABAoIBAHSLgUNA+OziSmOY\n"
	"ORsTMVKZfx7K3h68LfpEZKMk1pSpyseR/dYSMIUD1X7/7rBSDbXv4S6sgKghOtRz\n"
	"bqipeeO5/8cUGIjBXmN9EOms4wvr7mchFtgaXh35GMy7yb7oy9pZxPCf9JLtmmsI\n"
	"PrtLG/dMIZOWTisWm8X5Xmk6rVZVbdlP88g3pSj3e17PBL7EKwMffYiMe71f5AIc\n"
	"ZuSId8kAUOMS6SavHN1lDaH3joOxB7plMZoNaCDVX2+7360oaEG6Ohaz4WacCMPW\n"
	"2rJ8SkDsXoPJjdsGUvgQz+mTLPGzgGZVtDqrBmynxldKQ9CobwsPq7EhwmXfAWK1\n"
	"KuuJsoECgYEA2sfXHA9MkgidfrWQvGQu0avmQCe/dLxw5EG7macDHRpsa8LgiX6b\n"
	"TaVZHJZph8imBl5rIWAuirBv1GsgeGSCFtfZKQAOBYC3e97yWb6IEnjdkfltmp6n\n"
	"MOeBhJ58vVOyIa0EYhtUKBseo9g0QhrLhXd1430Ye9ZGKeXnmSitbDcCgYEAxafb\n"
	"+pfUM/UzFDLi8tjZkiK2qujvHMrMYbM8slRVO66zKkZCvXpQLv7BxK/k6YHL5ZP6\n"
	"uVBKdtru5eVlU/VUh+7FWG0bnL3Gr8ykBjLZtknaFz/31Bq6RVWkVWdIIZw2KW+1\n"
	"6H1rtVHqO6lKu0ZWT4X2OAMWX7pUzoRE8c/Vx8ECgYEAxclEvylVn/AJ8jNS1f38\n"
	"FbHCRt2oSHDT3odOgmpqdjUdL47OT38WB+wj06RnY0oSTk+tqk65xMgdUXxHro+u\n"
	"y9f3iwlxo6fqOSIlFt0ZRxndtco5PD+SBrREcxCU1NSFhcxU2hy6yEc8PAOJuvle\n"
	"ZRrKiQ7ew5XDeL1P0zbjEaECgYBPKM4CC6KR+IavdT3NMqnYTAzKYCW7a0D1c/pA\n"
	"FWRZVbstmBwMlJreZ2slIajVGAWX+W71nsFj3oTFD91IBb4H/smMg44GdT7Ik3Wx\n"
	"gdYNmoA8xYK0sMufDxCUn5uU0mIisDmzVd+4K4lawY9Ld30DtkwI3LuuNQrX9sNB\n"
	"8RHWQQKBgGpDFnnFPSChhVc1DINdjsIApsjG8xsifHshnrl7kTGx/5Udfw1xJDIo\n"
	"PkfAwDY7ZwsWQ19Ba7/wH36CEmP11u26LmqCTjuEkBns1Re+49aDix8WSCWj0QtJ\n"
	"8NknhTREVOrziidYqH9j9dBEMcN7B/f7lGsabSlj0MNuyAlFNtku\n"
	"-----END RSA PRIVATE KEY-----\n";

char test_full_seal[] = 
"{"
  "\"copyright\": \"Copyright © AppEsteem Corporation. All Rights Reserved.\","
  "\"description\": \"Digitally signed seal for Self Regulating Client Library for JavaScript (SRCLJS).\","
  "\"comments\": \"Generated file, do not edit! If the content of the 'signedSeal' property is changed in any way, including adding spaces or newline characters, the digital signature will be broken and the seal will be reported as being forged.\","
  "\"signedSeal\": \"{\\\"header\\\":{\\\"signature\\\":\\\"E6yCnh3vTw4wv/Su72l5VqcXX+gkrBAn27W0SPjmxnA4zB02apUOKHNFwly1pH6UiQnEz2JkyRDMdavEnMpQT75RLrEwIbiukucnqDf8TvG8HB0tgZ2SoQ3PxWn47O32kyvFqJxkfURDwkFjzZlkp6sR238LkFxsXO7snu9hVAtIef3nXt0OtbwpqAdL0atxgRwBHqgT/q7u53aHz9tSlZQA2IkAcIVNKnz7HdqYyVY0h6MPPbUuYua8ZTIyHhoU7v2LEnodQngTvQ4BvbyO2GuzwetQrJ23/DnFE1orEQhDd0L3ExVDbtSL+IiqW9w3KEf7vFlLulMVrPBijb6rQg==\\\",\\\"x509Cert\\\":\\\"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\\\"},\\\"seal\\\":{\\\"applicationIdentification\\\":{\\\"appId\\\":\\\"d5a7d18e-4426-4b7c-af25-000000003011\\\",\\\"sealId\\\":\\\"test11\\\",\\\"applicationType\\\":\\\"pe\\\"},\\\"attestations\\\":{\\\"address\\\":\\\"1 Main street, Anywhere, WA 98050\\\",\\\"certification\\\":\\\"yes\\\",\\\"valueProposition\\\":\\\"\\\",\\\"age\\\":\\\"12+\\\",\\\"audience\\\":[\\\"Consumer\\\"],\\\"category\\\":[\\\"SysTools & Utilities\\\"],\\\"monetization\\\":[\\\"Free\\\"],\\\"target\\\":[\\\"Windows XP\\\",\\\"Windows Vista\\\",\\\"Windows 7\\\",\\\"Windows 8\\\",\\\"Windows 10\\\"]},\\\"validDates\\\":{\\\"validForFilesSignedAfter\\\":\\\"2017-05-03T00:00:00+00:00\\\",\\\"validForFilesSignedBefore\\\":\\\"2018-05-03T00:00:00+00:00\\\"},\\\"distribution\\\":{\\\"whitelist\\\":{\\\"landingPages\\\":[\\\"http://tempuri.org\\\"],\\\"downloadUrls\\\":[\\\"http://tempuri.org\\\"]}},\\\"contents\\\":{\\\"files\\\":[{\\\"name\\\":\\\"SampleAp.exe\\\",\\\"majorVersion\\\":\\\"1\\\",\\\"thumbprint\\\":\\\"5290cd0b9eff8ebc15a5fb0530b9e5dc4de9d58a\\\",\\\"vendor\\\":\\\"SAMPLESOFT\\\"}]}}}\""
"}";

unsigned char test_seal[] = "{\"applicationIdentification\":{\"appId\":\"d5a7d18e-4426-4b7c-af25-000000003011\",\"sealId\":\"test11\",\"applicationType\":\"pe\"},\"attestations\":{\"address\":\"1 Main street, Anywhere, WA 98050\",\"certification\":\"yes\",\"valueProposition\":\"\",\"age\":\"12+\",\"audience\":[\"Consumer\"],\"category\":[\"SysTools & Utilities\"],\"monetization\":[\"Free\"],\"target\":[\"Windows XP\",\"Windows Vista\",\"Windows 7\",\"Windows 8\",\"Windows 10\"]},\"validDates\":{\"validForFilesSignedAfter\":\"2017-05-03T00:00:00+00:00\",\"validForFilesSignedBefore\":\"2018-05-03T00:00:00+00:00\"},\"distribution\":{\"whitelist\":{\"landingPages\":[\"http://tempuri.org\"],\"downloadUrls\":[\"http://tempuri.org\"]}},\"contents\":{\"files\":[{\"name\":\"SampleAp.exe\",\"majorVersion\":\"1\",\"thumbprint\":\"5290cd0b9eff8ebc15a5fb0530b9e5dc4de9d58a\",\"vendor\":\"SAMPLESOFT\"}]}}";

char test_seal_signature[] = "E6yCnh3vTw4wv/Su72l5VqcXX+gkrBAn27W0SPjmxnA4zB02apUOKHNFwly1pH6UiQnEz2JkyRDMdavEnMpQT75RLrEwIbiukucnqDf8TvG8HB0tgZ2SoQ3PxWn47O32kyvFqJxkfURDwkFjzZlkp6sR238LkFxsXO7snu9hVAtIef3nXt0OtbwpqAdL0atxgRwBHqgT/q7u53aHz9tSlZQA2IkAcIVNKnz7HdqYyVY0h6MPPbUuYua8ZTIyHhoU7v2LEnodQngTvQ4BvbyO2GuzwetQrJ23/DnFE1orEQhDd0L3ExVDbtSL+IiqW9w3KEf7vFlLulMVrPBijb6rQg==";

char test_seal_certificate[] = "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";

char test_seal_info[] = "c7e35ddc6de6ccbb5e1370c3b55fb3d85d17973aa4b890ef93f01faf8f01eaa2""\x1""2017-05-03T00:00:00+00:00""\x1""2018-05-03T00:00:00+00:00""\x1""SampleAp.exe""\x1""SAMPLESOFT""\x1""1""\x1""5290cd0b9eff8ebc15a5fb0530b9e5dc4de9d58a""\x1";

/* From taggant3.c*/
UNSIGNED32 taggant3_validate_seal_signature(unsigned char* json, unsigned int jsonlen, char* signature, char* cert);
PINFO taggant3_get_seal_info_from_buffer(char *fullsealbuf);

typedef struct _io_map
{
	char* data;
	UNSIGNED64 size;
	UNSIGNED64 pos;
} io_map;

size_t __DECLARATION fileio_fread(io_map* fin, void* buffer, size_t size)
{
	size_t count = size;
	if (fin->pos + count > fin->size)
		count = (size_t)(fin->size - fin->pos);
	memcpy(buffer, fin->data + fin->pos, count);
	fin->pos += count;
	return count;
}
int __DECLARATION fileio_fseek(io_map* fin, UNSIGNED64 offset, int type)
{
	int fail = 0;
	switch (type)
	{
	case SEEK_SET:
		if (offset <= fin->size)
			fin->pos = offset;
		else
			fail = 1;
		break;
	case SEEK_CUR:
		if (fin->pos + offset <= fin->size)
			fin->pos += offset;
		else
			fail = 1;
		break;
	case SEEK_END:
		if (offset <= fin->size)
			fin->pos = fin->size - offset;
		else
			fail = 1;
		break;
	default:
		fail = 1;
	}
	return fail;
}
UNSIGNED64 __DECLARATION fileio_ftell(io_map* fin)
{
	return fin->pos;
}

int test_taggant3_validate_seal_signature()
{
	if (TNOERR != taggant3_validate_seal_signature(test_seal, sizeof(test_seal) - 1, test_seal_signature, test_seal_certificate))
	{
		return 0;
	}

	return 1;
}

int test_taggant3_get_seal_info_from_buffer()
{
	char* seal_info = taggant3_get_seal_info_from_buffer(test_full_seal);
	if (!seal_info)
	{
		return 0;
	}
	if (0 != strcmp(seal_info, test_seal_info))
	{
		free(seal_info);
		return 0;
	}
	free(seal_info);

	return 1;
}

int test_taggant3_taggant_generation()
{
	UNSIGNED32 err = TERROR;
	UNSIGNED64 ltime;
	PTAGGANTOBJ tagobj;
	PTAGGANTCONTEXT pCtx;
	PACKERINFO packer_info;
	UNSIGNED8 ignorehmh = 1;
	io_map json_seal;
	UNSIGNED32 taggantsize = 0x10000;
	char* taggant = NULL;

	/* Make sure the license or the taggant is valid */
	if (TNOERR == TaggantGetLicenseExpirationDate(license, &ltime))
	{
		/* Create taggant context */
		if (TNOERR == TaggantContextNewEx(&pCtx))
		{
			/* Vendor should check version flow here! */
			pCtx->FileReadCallBack = (size_t(__DECLARATION *)(void*, void*, size_t))fileio_fread;
			pCtx->FileSeekCallBack = (int (__DECLARATION *)(void*, UNSIGNED64, int))fileio_fseek;
			pCtx->FileTellCallBack = (UNSIGNED64(__DECLARATION *)(void*))fileio_ftell;
			if (TNOERR == TaggantObjectNewEx(NULL, TAGGANT_LIBRARY_VERSION3, TAGGANT_PESEALFILE, &tagobj))
			{
				json_seal.data = test_full_seal;
				json_seal.size = sizeof(test_full_seal);
				json_seal.pos = 0;
				if (TNOERR == TaggantComputeHashes(pCtx, tagobj, &json_seal, 0, 0, 0))
				{
					/* set packer information */
					memset(&packer_info, 0, sizeof(PACKERINFO));
					packer_info.PackerId = 1;
					packer_info.VersionMajor = SIGNTOOL_VERSION >> 16 & 0xFF;
					packer_info.VersionMinor = SIGNTOOL_VERSION >> 8 & 0xFF;
					packer_info.VersionBuild = SIGNTOOL_VERSION & 0xFF;
					if (TNOERR == TaggantPutInfo(tagobj, EPACKERINFO, sizeof(PACKERINFO), (char*)&packer_info))
					{
						if (TNOERR == TaggantPutInfo(tagobj, EIGNOREHMH, sizeof(UNSIGNED8), (char*)&ignorehmh))
						{
							/* Set contributor list information */
							if (TNOERR == TaggantPutInfo(tagobj, ECONTRIBUTORLIST, 23, "CONTRIBUTORS LIST HERE")) /* 23 is strlen("CONTRIBUTORS LIST HERE") + 1 */
							{
								/* try to put timestamp */
								TaggantPutTimestamp(tagobj, tsurl, 50);
								/* if (TNOERR == TaggantPutTimestamp(tagobj, tsurl, 50)) do not require connection while testing */
								{
									/* allocate the approximate buffer for CMS */
									taggant = (char*)malloc(taggantsize);
									if (taggant)
									{
										// if the allocated buffer is not sufficient then allocate bigger buffer
										err = TaggantPrepare(tagobj, (PVOID)license, taggant, &taggantsize);
										if (err == TINSUFFICIENTBUFFER)
										{
											taggantsize *= 2;
											taggant = (char*)realloc(taggant, taggantsize);
											err = TaggantPrepare(tagobj, (PVOID)license, taggant, &taggantsize);
										}
										if (err == TNOERR)
										{
											/* The taggant changes every time because of the timestamp, cannot
											   memcmp with a known value */
										}
										free(taggant);
									}
								}
							}
						}
					}
				}
				TaggantObjectFree(tagobj);
			}
			TaggantContextFree(pCtx);
		}
	}

	return err == TNOERR;
}

int main(int argc, char* argv[])
{
	UNSIGNED64 version;
	if (TNOERR != TaggantInitializeLibrary(NULL, &version))
	{
		printf("Taggant library initialization failed\n");
		TaggantFinalizeLibrary();
		return -1;
	}

	if (!test_taggant3_validate_seal_signature())
	{
		printf("Seal signature validation test failed\n");
		TaggantFinalizeLibrary();
		return -1;
	}

	/* allow profiling */
	for (int i = 0; i < 100000; i++)
	{
		if (!test_taggant3_get_seal_info_from_buffer())
		{
			printf("Getting information from seal failed\n");
			TaggantFinalizeLibrary();
			return -1;
		}
	}

	if (!test_taggant3_taggant_generation())
	{
		printf("Taggant generation failed\n");
		TaggantFinalizeLibrary();
		return -1;
	}

	printf("All tests passed\n");
	TaggantFinalizeLibrary();
	return 0;
}

