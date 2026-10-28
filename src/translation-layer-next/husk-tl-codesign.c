/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * husk-tl-codesign.c: On-device Mach-O codesigner for Husk (iOS 15.5+ / macOS).
 *
 * Implements code signing in pure C using only Apple's Security.framework,
 * CommonCrypto, and CoreFoundation. Does NOT depend on OpenSSL, command-line
 * tools, or any AGPL code.
 *
 * Background & Apple Code Signing Architecture:
 * ---------------------------------------------
 * On modern iOS (iOS 15 through iOS 26+), dlopen() enforces Apple's Library
 * Validation (LV). For an in-process translation layer to dynamically load
 * Ahead-Of-Time (AOT) compiled arm64 dylibs without JIT entitlement or
 * debugger bypasses, the dylibs MUST be signed on-device with the same Apple
 * Developer certificate and Team ID that signed the host app (or signed
 * with an ad-hoc signature if library validation is relaxed, e.g. on macOS).
 *
 * Apple Mach-O Code Signature Structure:
 * 1. LC_CODE_SIGNATURE load command:
 *    Points to a file offset (dataoff) and byte count (datasize) within the
 *    __LINKEDIT segment.
 *
 * 2. Embedded Signature SuperBlob (magic 0xfade0cc0):
 *    A container holding multiple indexed blobs:
 *    - Slot 0 (CSSLOT_CODEDIRECTORY, magic 0xfade0c02):
 *        CodeDirectory version 0x20400 (supporting execSegBase/Limit/Flags).
 *        Contains SHA-256 hashes of every 16 KiB (2^14 bytes) page of the
 *        file up to the start of the signature (codeLimit).
 *        Preceding the code slot hashes are negative index slots:
 *          Slot -1: Info.plist SHA-256 (all zeroes for dylibs without plist).
 *          Slot -2: Requirements blob SHA-256.
 *        Also embeds the dylib identifier string and the Developer Team ID.
 *    - Slot 1 (CSSLOT_REQUIREMENTS, magic 0xfade0c01):
 *        Designated requirement vector enforcing identifier matching.
 *    - Slot 2 (CSSLOT_SIGNATURESLOT, magic 0xfade0b01):
 *        BlobWrapper containing a CMS (PKCS#7) SignedData DER structure.
 *        Signs the SHA-256 digest of the CodeDirectory (CDHash) using the
 *        developer's RSA or ECDSA private key.
 *        Contains Apple-specific signed attributes (1.2.840.113635.100.9.1
 *        and 1.2.840.113635.100.9.2) embedding the CDHashes.
 *
 * Uncertainties & Known Limits:
 * - Developer certificate chains must be valid X.509 DER. If intermediate CA
 *   certificates are included in the .p12 (kSecImportItemCertChain), they are
 *   automatically embedded into the CMS certificates set so iOS trust
 *   evaluation can verify back to Apple Worldwide Developer Relations CA.
 * - This implementation targets arm64 64-bit Mach-O dylibs (Mach-O magic
 *   MH_MAGIC_64), which covers all iOS 15+ devices and Apple Silicon Macs.
 */

#include "husk-tl-codesign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <TargetConditionals.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

/* ------------------------------------------------------------------ Constants */

#define CSMAGIC_REQUIREMENT         0xfade0c00
#define CSMAGIC_REQUIREMENTS        0xfade0c01
#define CSMAGIC_CODEDIRECTORY       0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE  0xfade0cc0
#define CSMAGIC_BLOBWRAPPER         0xfade0b01

#define CSSLOT_CODEDIRECTORY        0
#define CSSLOT_REQUIREMENTS         2
#define CSSLOT_SIGNATURESLOT        0x10000

#define CS_HASHTYPE_SHA256          2
#define CS_SHA256_LEN               32
#define CS_PAGE_SIZE_LOG2           14  /* 16384 bytes (16 KiB) */
#define CS_PAGE_SIZE                (1 << CS_PAGE_SIZE_LOG2)

#define CS_ADHOC                    0x2
#define CS_SUPPORTSEXECSEG          0x20400

/* ------------------------------------------------------------------ Dynamic Buffer */

typedef struct {
    uint8_t *b;
    size_t n, cap;
} cs_buf;

static void buf_init(cs_buf *b) {
    b->b = NULL;
    b->n = 0;
    b->cap = 0;
}

static void buf_free(cs_buf *b) {
    free(b->b);
    b->b = NULL;
    b->n = 0;
    b->cap = 0;
}

static bool buf_reserve(cs_buf *b, size_t extra) {
    if (b->n + extra > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 512;
        while (ncap < b->n + extra) ncap *= 2;
        uint8_t *p = (uint8_t *)realloc(b->b, ncap);
        if (!p) return false;
        b->b = p;
        b->cap = ncap;
    }
    return true;
}

static void buf_put(cs_buf *b, const void *p, size_t len) {
    if (len == 0) return;
    if (buf_reserve(b, len)) {
        memcpy(b->b + b->n, p, len);
        b->n += len;
    }
}

static void buf_put_byte(cs_buf *b, uint8_t byte) {
    buf_put(b, &byte, 1);
}

static void buf_put_u32_be(cs_buf *b, uint32_t val) {
    uint8_t d[4] = {
        (uint8_t)(val >> 24),
        (uint8_t)(val >> 16),
        (uint8_t)(val >> 8),
        (uint8_t)val
    };
    buf_put(b, d, 4);
}

static void buf_put_u64_be(cs_buf *b, uint64_t val) {
    buf_put_u32_be(b, (uint32_t)(val >> 32));
    buf_put_u32_be(b, (uint32_t)val);
}

/* ------------------------------------------------------------------ ASN.1 DER Helpers */

/* Writes an ASN.1 definite length octet sequence */
static void der_put_length(cs_buf *b, size_t len) {
    if (len < 128) {
        buf_put_byte(b, (uint8_t)len);
    } else if (len < 256) {
        buf_put_byte(b, 0x81);
        buf_put_byte(b, (uint8_t)len);
    } else if (len < 65536) {
        buf_put_byte(b, 0x82);
        buf_put_byte(b, (uint8_t)(len >> 8));
        buf_put_byte(b, (uint8_t)len);
    } else {
        buf_put_byte(b, 0x83);
        buf_put_byte(b, (uint8_t)(len >> 16));
        buf_put_byte(b, (uint8_t)(len >> 8));
        buf_put_byte(b, (uint8_t)len);
    }
}

/* Writes Tag-Length-Value */
static void der_put_tlv(cs_buf *b, uint8_t tag, const uint8_t *val, size_t len) {
    buf_put_byte(b, tag);
    der_put_length(b, len);
    if (len) buf_put(b, val, len);
}

/* Wraps the buffer segment starting at content_start with an ASN.1 constructed tag */
static void der_wrap(cs_buf *b, uint8_t tag, size_t content_start) {
    size_t content_len = b->n - content_start;
    cs_buf tmp;
    buf_init(&tmp);
    buf_put_byte(&tmp, tag);
    der_put_length(&tmp, content_len);
    size_t header_len = tmp.n;
    if (buf_reserve(b, header_len)) {
        memmove(b->b + content_start + header_len, b->b + content_start, content_len);
        memcpy(b->b + content_start, tmp.b, header_len);
        b->n += header_len;
    }
    buf_free(&tmp);
}

/* Parses Tag-Length-Value header from raw buffer */
static bool parse_tlv(const uint8_t *p, size_t len, size_t *pos, uint8_t *tag, size_t *header_len, size_t *v_len) {
    if (*pos >= len) return false;
    *tag = p[*pos];
    if (*pos + 1 >= len) return false;
    uint8_t l1 = p[*pos + 1];
    if (!(l1 & 0x80)) {
        *header_len = 2;
        *v_len = l1;
    } else {
        size_t n = l1 & 0x7f;
        if (n == 0 || n > 4 || *pos + 2 + n > len) return false;
        size_t vl = 0;
        for (size_t i = 0; i < n; i++) vl = (vl << 8) | p[*pos + 2 + i];
        *header_len = 2 + n;
        *v_len = vl;
    }
    if (*pos + *header_len + *v_len > len) return false;
    return true;
}

/* ------------------------------------------------------------------ X.509 Certificate Parser */

typedef struct {
    const uint8_t *serial_ptr;
    size_t serial_len;
    const uint8_t *issuer_ptr;
    size_t issuer_len;
    char team_id[64];
    int64_t not_after_epoch;
    bool is_rsa;
} cert_meta;

static bool parse_cert_der(const uint8_t *cert_der, size_t cert_len, cert_meta *out) {
    memset(out, 0, sizeof(*out));
    out->is_rsa = true;

    size_t pos = 0, hlen = 0, vlen = 0;
    uint8_t tag = 0;

    /* Outer Certificate SEQUENCE */
    if (!parse_tlv(cert_der, cert_len, &pos, &tag, &hlen, &vlen) || tag != 0x30) return false;
    pos += hlen;

    /* TBSCertificate SEQUENCE */
    if (!parse_tlv(cert_der, cert_len, &pos, &tag, &hlen, &vlen) || tag != 0x30) return false;
    size_t tbs_end = pos + hlen + vlen;
    pos += hlen;

    /* Optional Version [0] EXPLICIT */
    if (parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) && tag == 0xa0) {
        pos += hlen + vlen;
    }

    /* Serial Number INTEGER */
    if (!parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) || tag != 0x02) return false;
    out->serial_ptr = cert_der + pos;
    out->serial_len = hlen + vlen;
    pos += hlen + vlen;

    /* Signature Algorithm SEQUENCE */
    if (!parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) || tag != 0x30) return false;
    pos += hlen + vlen;

    /* Issuer Name SEQUENCE */
    if (!parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) || tag != 0x30) return false;
    out->issuer_ptr = cert_der + pos;
    out->issuer_len = hlen + vlen;
    pos += hlen + vlen;

    /* Validity SEQUENCE */
    if (!parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) || tag != 0x30) return false;
    size_t val_end = pos + hlen + vlen;
    pos += hlen;
    /* notBefore (skip) */
    if (!parse_tlv(cert_der, val_end, &pos, &tag, &hlen, &vlen)) return false;
    pos += hlen + vlen;
    /* notAfter */
    if (!parse_tlv(cert_der, val_end, &pos, &tag, &hlen, &vlen)) return false;
    if (vlen >= 13) {
        const char *t_str = (const char *)(cert_der + pos + hlen);
        struct tm tm_val;
        memset(&tm_val, 0, sizeof(tm_val));
        if (tag == 0x17) { /* UTCTime YYMMDDHHMMSSZ */
            int yy = (t_str[0] - '0') * 10 + (t_str[1] - '0');
            tm_val.tm_year = (yy < 50 ? 2000 + yy : 1900 + yy) - 1900;
            tm_val.tm_mon  = (t_str[2] - '0') * 10 + (t_str[3] - '0') - 1;
            tm_val.tm_mday = (t_str[4] - '0') * 10 + (t_str[5] - '0');
            tm_val.tm_hour = (t_str[6] - '0') * 10 + (t_str[7] - '0');
            tm_val.tm_min  = (t_str[8] - '0') * 10 + (t_str[9] - '0');
            tm_val.tm_sec  = (t_str[10] - '0') * 10 + (t_str[11] - '0');
            out->not_after_epoch = timegm(&tm_val);
        } else if (tag == 0x18 && vlen >= 15) { /* GeneralizedTime YYYYMMDDHHMMSSZ */
            int yyyy = (t_str[0] - '0') * 1000 + (t_str[1] - '0') * 100 + (t_str[2] - '0') * 10 + (t_str[3] - '0');
            tm_val.tm_year = yyyy - 1900;
            tm_val.tm_mon  = (t_str[4] - '0') * 10 + (t_str[5] - '0') - 1;
            tm_val.tm_mday = (t_str[6] - '0') * 10 + (t_str[7] - '0');
            tm_val.tm_hour = (t_str[8] - '0') * 10 + (t_str[9] - '0');
            tm_val.tm_min  = (t_str[10] - '0') * 10 + (t_str[11] - '0');
            tm_val.tm_sec  = (t_str[12] - '0') * 10 + (t_str[13] - '0');
            out->not_after_epoch = timegm(&tm_val);
        }
    }
    pos = val_end;

    /* Subject Name SEQUENCE */
    if (!parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) || tag != 0x30) return false;
    size_t subj_end = pos + hlen + vlen;
    /* Find OrganizationalUnitName (OU, OID 2.5.4.11 -> 06 03 55 04 0b) inside Subject */
    for (size_t i = pos; i + 7 < subj_end; i++) {
        if (cert_der[i] == 0x06 && cert_der[i+1] == 0x03 && cert_der[i+2] == 0x55 &&
            cert_der[i+3] == 0x04 && cert_der[i+4] == 0x0b) {
            size_t val_pos = i + 5;
            uint8_t str_tag = 0; size_t str_hlen = 0, str_vlen = 0;
            if (parse_tlv(cert_der, subj_end, &val_pos, &str_tag, &str_hlen, &str_vlen)) {
                size_t copy_len = str_vlen < sizeof(out->team_id) - 1 ? str_vlen : sizeof(out->team_id) - 1;
                memcpy(out->team_id, cert_der + val_pos + str_hlen, copy_len);
                out->team_id[copy_len] = '\0';
                break;
            }
        }
    }
    pos = subj_end;

    /* SubjectPublicKeyInfo SEQUENCE */
    if (parse_tlv(cert_der, tbs_end, &pos, &tag, &hlen, &vlen) && tag == 0x30) {
        size_t spki_pos = pos + hlen;
        uint8_t alg_tag = 0; size_t alg_hlen = 0, alg_vlen = 0;
        if (parse_tlv(cert_der, tbs_end, &spki_pos, &alg_tag, &alg_hlen, &alg_vlen) && alg_tag == 0x30) {
            /* Check for id-ecPublicKey (1.2.840.10045.2.1: 06 07 2a 86 48 ce 3d 02 01) */
            static const uint8_t ec_oid[] = { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
            if (alg_vlen >= sizeof(ec_oid) &&
                memcmp(cert_der + spki_pos + alg_hlen, ec_oid, sizeof(ec_oid)) == 0) {
                out->is_rsa = false;
            }
        }
    }

    return true;
}

/* ------------------------------------------------------------------ Base64 Encoder */

static char *b64_encode(const uint8_t *data, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        size_t rem = len - i;
        uint32_t a = data[i++];
        uint32_t b = (rem > 1) ? data[i++] : 0;
        uint32_t c = (rem > 2) ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = tbl[(triple >> 18) & 0x3F];
        out[j++] = tbl[(triple >> 12) & 0x3F];
        out[j++] = (rem > 1) ? tbl[(triple >> 6) & 0x3F] : '=';
        out[j++] = (rem > 2) ? tbl[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

/* ------------------------------------------------------------------ CMS SignedData Generator */

static const uint8_t sha256_alg_null[] = {
    0x30, 0x0d,
      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
      0x05, 0x00
};

/*
 * Issuer certificates to carry beside the developer certificate, for when the .p12 has none (a store's export holds only the
 * developer certificate and its key): set by husk_codesign_chain_from_executable from the certificates in the app's own signature,
 * which the store signed with this same certificate and its full chain.
 */
#define CHAIN_MAX 4
static struct { uint8_t *der; size_t len; } g_chain[CHAIN_MAX];
static int g_nchain;

static bool chain_has(const uint8_t *der, size_t len)
{
    for (int i = 0; i < g_nchain; i++) if (g_chain[i].len == len && !memcmp(g_chain[i].der, der, len)) return true;
    return false;
}

static bool build_cms_signed_data(const uint8_t *cdhash, size_t cdhash_len,
                                  const uint8_t *leaf_cert_der, size_t leaf_cert_len,
                                  const cert_meta *meta,
                                  CFArrayRef extra_certs,
                                  SecKeyRef privKey,
                                  cs_buf *out_cms)
{
    cs_buf attrs;
    buf_init(&attrs);

    /* 1. contentType (OID 1.2.840.113549.1.9.3 -> 1.2.840.113549.1.7.1 pkcs7-data) */
    static const uint8_t a0[] = {
        0x30, 0x18,
          0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
          0x31, 0x0b,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
    };
    buf_put(&attrs, a0, sizeof(a0));

    /* 2. signingTime (OID 1.2.840.113549.1.9.5 -> UTCTime YYMMDDhhmmssZ) */
    time_t now = time(NULL);
    struct tm tm_now;
    gmtime_r(&now, &tm_now);
    char time_str[16];
    snprintf(time_str, sizeof(time_str), "%02d%02d%02d%02d%02d%02dZ",
             tm_now.tm_year % 100, tm_now.tm_mon + 1, tm_now.tm_mday,
             tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);
    buf_put_byte(&attrs, 0x30);
    der_put_length(&attrs, 28);
    static const uint8_t oid_st[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05 };
    buf_put(&attrs, oid_st, sizeof(oid_st));
    buf_put_byte(&attrs, 0x31);
    der_put_length(&attrs, 15);
    der_put_tlv(&attrs, 0x17, (const uint8_t *)time_str, 13);

    /* 3. messageDigest (OID 1.2.840.113549.1.9.4 -> OCTET STRING CDHash 32 bytes) */
    buf_put_byte(&attrs, 0x30);
    der_put_length(&attrs, 47);
    static const uint8_t oid_md[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04 };
    buf_put(&attrs, oid_md, sizeof(oid_md));
    buf_put_byte(&attrs, 0x31);
    der_put_length(&attrs, 34);
    der_put_tlv(&attrs, 0x04, cdhash, 32);

    /* 4. Apple CDHash (OID 1.2.840.113635.100.9.2 -> SEQUENCE of { sha256, hash }) */
    static const uint8_t a3_hdr[] = {
        0x30, 0x3c,
          0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02,
          0x31, 0x2f,
            0x30, 0x2d,
              0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
              0x04, 0x20
    };
    buf_put(&attrs, a3_hdr, sizeof(a3_hdr));
    buf_put(&attrs, cdhash, 32);

    /* 5. Apple CDHashes plist (OID 1.2.840.113635.100.9.1 -> base64 20-byte truncated CDHash) */
    char *b64 = b64_encode(cdhash, 20);
    char plist[512];
    int plen = snprintf(plist, sizeof(plist),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "\t<key>cdhashes</key>\n"
        "\t<array>\n"
        "\t\t<data>\n"
        "\t\t%s\n"
        "\t\t</data>\n"
        "\t</array>\n"
        "</dict>\n"
        "</plist>\n", b64 ? b64 : "");
    free(b64);

    cs_buf a4_inner;
    buf_init(&a4_inner);
    der_put_tlv(&a4_inner, 0x04, (const uint8_t *)plist, (size_t)plen);
    der_wrap(&a4_inner, 0x31, 0); /* SET */
    static const uint8_t oid_apple_cdhashes[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01 };
    cs_buf a4;
    buf_init(&a4);
    buf_put(&a4, oid_apple_cdhashes, sizeof(oid_apple_cdhashes));
    buf_put(&a4, a4_inner.b, a4_inner.n);
    der_wrap(&a4, 0x30, 0); /* SEQUENCE */
    buf_put(&attrs, a4.b, a4.n);
    buf_free(&a4_inner);
    buf_free(&a4);

    /* RFC 5652: Compute digest over EXPLICIT SET OF tag (0x31) + length + attribute contents */
    cs_buf to_hash;
    buf_init(&to_hash);
    buf_put_byte(&to_hash, 0x31);
    der_put_length(&to_hash, attrs.n);
    buf_put(&to_hash, attrs.b, attrs.n);

    uint8_t attrs_digest[32];
    CC_SHA256(to_hash.b, (CC_LONG)to_hash.n, attrs_digest);
    buf_free(&to_hash);

    /* Sign attrs_digest with SecKeyCreateSignature */
    CFDataRef digestData = CFDataCreate(kCFAllocatorDefault, attrs_digest, sizeof(attrs_digest));
    CFErrorRef error = NULL;
    CFStringRef alg = meta->is_rsa ? kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                                   : kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    CFDataRef sig = SecKeyCreateSignature(privKey, alg, digestData, &error);
    CFRelease(digestData);
    if (!sig) {
        if (error) CFRelease(error);
        buf_free(&attrs);
        return false;
    }

    const uint8_t *sig_bytes = CFDataGetBytePtr(sig);
    size_t sig_len = CFDataGetLength(sig);

    /* Build SignerInfo */
    cs_buf sinfo;
    buf_init(&sinfo);

    /* version = 1 */
    static const uint8_t ver1[] = { 0x02, 0x01, 0x01 };
    buf_put(&sinfo, ver1, sizeof(ver1));

    /* sid: IssuerAndSerialNumber (SEQUENCE { issuer, serialNumber }) */
    size_t sid_start = sinfo.n;
    buf_put(&sinfo, meta->issuer_ptr, meta->issuer_len);
    buf_put(&sinfo, meta->serial_ptr, meta->serial_len);
    der_wrap(&sinfo, 0x30, sid_start);

    /* digestAlgorithm: sha256 */
    buf_put(&sinfo, sha256_alg_null, sizeof(sha256_alg_null));

    /* [0] IMPLICIT signedAttrs */
    buf_put_byte(&sinfo, 0xa0);
    der_put_length(&sinfo, attrs.n);
    buf_put(&sinfo, attrs.b, attrs.n);
    buf_free(&attrs);

    /* signatureAlgorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11) or ecdsa-with-SHA256 */
    if (meta->is_rsa) {
        static const uint8_t rsa_alg_null[] = {
            0x30, 0x0d,
              0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
              0x05, 0x00
        };
        buf_put(&sinfo, rsa_alg_null, sizeof(rsa_alg_null));
    } else {
        static const uint8_t ec_alg[] = {
            0x30, 0x0a,
              0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
        };
        buf_put(&sinfo, ec_alg, sizeof(ec_alg));
    }

    /* signature: OCTET STRING */
    der_put_tlv(&sinfo, 0x04, sig_bytes, sig_len);
    CFRelease(sig);
    der_wrap(&sinfo, 0x30, 0); /* SignerInfo SEQUENCE */
    der_wrap(&sinfo, 0x31, 0); /* signerInfos SET OF */

    /* Build SignedData */
    cs_buf sdata;
    buf_init(&sdata);
    buf_put(&sdata, ver1, sizeof(ver1));

    /* digestAlgorithms SET OF { sha256 } */
    cs_buf dalg;
    buf_init(&dalg);
    buf_put(&dalg, sha256_alg_null, sizeof(sha256_alg_null));
    der_wrap(&dalg, 0x31, 0);
    buf_put(&sdata, dalg.b, dalg.n);
    buf_free(&dalg);

    /* encapContentInfo: SEQUENCE { OID pkcs7-data } (detached content) */
    static const uint8_t encap[] = { 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 };
    buf_put(&sdata, encap, sizeof(encap));

    /* [0] IMPLICIT certificates */
    size_t certs_start = sdata.n;
    buf_put(&sdata, leaf_cert_der, leaf_cert_len);
    if (extra_certs) {
        CFIndex count = CFArrayGetCount(extra_certs);
        for (CFIndex i = 0; i < count; i++) {
            SecCertificateRef c = (SecCertificateRef)CFArrayGetValueAtIndex(extra_certs, i);
            CFDataRef cd = SecCertificateCopyData(c);
            if (cd) {
                if ((CFDataGetLength(cd) != leaf_cert_len ||
                     memcmp(CFDataGetBytePtr(cd), leaf_cert_der, leaf_cert_len) != 0)
                    && !chain_has(CFDataGetBytePtr(cd), (size_t)CFDataGetLength(cd))) {
                    buf_put(&sdata, CFDataGetBytePtr(cd), CFDataGetLength(cd));
                }
                CFRelease(cd);
            }
        }
    }
    for (int i = 0; i < g_nchain; i++)
        if (g_chain[i].len != leaf_cert_len || memcmp(g_chain[i].der, leaf_cert_der, leaf_cert_len) != 0)
            buf_put(&sdata, g_chain[i].der, g_chain[i].len);
    der_wrap(&sdata, 0xa0, certs_start);

    /* Append signerInfos SET OF */
    buf_put(&sdata, sinfo.b, sinfo.n);
    buf_free(&sinfo);

    der_wrap(&sdata, 0x30, 0); /* SignedData SEQUENCE */

    /* Wrap in ContentInfo (pkcs7-signedData) */
    cs_buf cinfo;
    buf_init(&cinfo);
    static const uint8_t oid_signed_data[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };
    buf_put(&cinfo, oid_signed_data, sizeof(oid_signed_data));
    der_wrap(&sdata, 0xa0, 0); /* [0] EXPLICIT SignedData */
    buf_put(&cinfo, sdata.b, sdata.n);
    buf_free(&sdata);
    der_wrap(&cinfo, 0x30, 0); /* ContentInfo SEQUENCE */

    *out_cms = cinfo;
    return true;
}

/* ------------------------------------------------------------------ PKCS#12 Helper */

#if !TARGET_OS_IPHONE
/*
 * On macOS, SecPKCS12Import defaults to importing identities into the user's
 * login keychain, which prompts the user with a GUI dialog when signing.
 * To avoid prompts and keychain pollution during testing, we create an unlocked
 * temporary keychain, import into it, and delete the keychain when finished.
 */
static SecKeychainRef macos_create_temp_keychain(char *kc_path_out, size_t kc_path_len) {
    snprintf(kc_path_out, kc_path_len, "/tmp/.husk_cs_%d_%lu.keychain", getpid(), (unsigned long)time(NULL));
    unlink(kc_path_out);
    SecKeychainRef kc = NULL;
    OSStatus st = SecKeychainCreate(kc_path_out, 4, "temp", false, NULL, &kc);
    if (st != errSecSuccess) return NULL;
    SecKeychainUnlock(kc, 4, "temp", true);
    return kc;
}

static void macos_cleanup_temp_keychain(SecKeychainRef kc, const char *kc_path) {
    if (kc) {
        SecKeychainDelete(kc);
        CFRelease(kc);
    }
    if (kc_path && kc_path[0]) {
        unlink(kc_path);
    }
}
#endif

bool husk_p12_info(const uint8_t *p12, size_t p12_len, const char *password,
                   char *team_id, size_t team_id_len,
                   double *not_after_epoch,
                   char *err, size_t errlen)
{
    if (err && errlen > 0) err[0] = '\0';
    if (!p12 || p12_len == 0) {
        if (err && errlen > 0) snprintf(err, errlen, "p12 bundle is empty");
        return false;
    }

    CFDataRef data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, p12, (CFIndex)p12_len, kCFAllocatorNull);
    CFStringRef pass = CFStringCreateWithCString(kCFAllocatorDefault, password ? password : "", kCFStringEncodingUTF8);

#if !TARGET_OS_IPHONE
    char kc_path[256] = {0};
    SecKeychainRef kc = macos_create_temp_keychain(kc_path, sizeof(kc_path));
    const void *keys[] = { kSecImportExportPassphrase, kSecImportExportKeychain };
    const void *values[] = { pass, kc };
    CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, kc ? 2 : 1,
                                                 &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
#else
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { pass };
    CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                                 &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
#endif

    CFArrayRef items = NULL;
    OSStatus st = SecPKCS12Import(data, options, &items);
    CFRelease(options);
    CFRelease(pass);
    CFRelease(data);

    if (st != errSecSuccess || !items || CFArrayGetCount(items) == 0) {
#if !TARGET_OS_IPHONE
        macos_cleanup_temp_keychain(kc, kc_path);
#endif
        if (items) CFRelease(items);
        if (err && errlen > 0) snprintf(err, errlen, "SecPKCS12Import failed (status %d, invalid password or corrupted .p12)", (int)st);
        return false;
    }

    CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecImportItemIdentity);
    SecCertificateRef cert = NULL;
    if (identity) {
        SecIdentityCopyCertificate(identity, &cert);
    } else {
        cert = (SecCertificateRef)CFDictionaryGetValue(dict, kSecImportItemCertChain);
        if (cert) CFRetain(cert);
    }

    if (!cert) {
        CFRelease(items);
#if !TARGET_OS_IPHONE
        macos_cleanup_temp_keychain(kc, kc_path);
#endif
        if (err && errlen > 0) snprintf(err, errlen, "No certificate found in .p12 bundle");
        return false;
    }

    CFDataRef certData = SecCertificateCopyData(cert);
    cert_meta meta;
    bool parsed = parse_cert_der(CFDataGetBytePtr(certData), (size_t)CFDataGetLength(certData), &meta);
    CFRelease(certData);
    CFRelease(cert);
    CFRelease(items);

#if !TARGET_OS_IPHONE
    macos_cleanup_temp_keychain(kc, kc_path);
#endif

    if (!parsed) {
        if (err && errlen > 0) snprintf(err, errlen, "Failed to parse X.509 certificate in .p12");
        return false;
    }

    if (team_id && team_id_len > 0) {
        snprintf(team_id, team_id_len, "%s", meta.team_id);
    }
    if (not_after_epoch) {
        *not_after_epoch = (double)meta.not_after_epoch;
    }

    return true;
}

/* ------------------------------------------------------------------ Mach-O Dylib Codesigner */

bool husk_codesign_dylib(const char *path, const uint8_t *p12, size_t p12_len, const char *password,
                         char *err, size_t errlen)
{
    if (err && errlen > 0) err[0] = '\0';
    if (!path || !path[0]) {
        if (err && errlen > 0) snprintf(err, errlen, "Invalid dylib path");
        return false;
    }

    bool has_identity = (p12 != NULL && p12_len > 0);
    cert_meta meta;
    memset(&meta, 0, sizeof(meta));

    CFArrayRef items = NULL;
    SecIdentityRef identity = NULL;
    SecCertificateRef cert = NULL;
    SecKeyRef privKey = NULL;
    CFArrayRef chain = NULL;
    CFDataRef certData = NULL;

#if !TARGET_OS_IPHONE
    char kc_path[256] = {0};
    SecKeychainRef kc = NULL;
#endif

    if (has_identity) {
        CFDataRef p12_data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, p12, (CFIndex)p12_len, kCFAllocatorNull);
        CFStringRef pass = CFStringCreateWithCString(kCFAllocatorDefault, password ? password : "", kCFStringEncodingUTF8);

#if !TARGET_OS_IPHONE
        kc = macos_create_temp_keychain(kc_path, sizeof(kc_path));
        const void *keys[] = { kSecImportExportPassphrase, kSecImportExportKeychain };
        const void *values[] = { pass, kc };
        CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, kc ? 2 : 1,
                                                     &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
#else
        const void *keys[] = { kSecImportExportPassphrase };
        const void *values[] = { pass };
        CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                                     &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
#endif

        OSStatus st = SecPKCS12Import(p12_data, options, &items);
        CFRelease(options);
        CFRelease(pass);
        CFRelease(p12_data);

        if (st != errSecSuccess || !items || CFArrayGetCount(items) == 0) {
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
            if (items) CFRelease(items);
            if (err && errlen > 0) snprintf(err, errlen, "SecPKCS12Import failed (status %d)", (int)st);
            return false;
        }

        CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecImportItemIdentity);
        chain = (CFArrayRef)CFDictionaryGetValue(dict, kSecImportItemCertChain);

        if (!identity || SecIdentityCopyCertificate(identity, &cert) != errSecSuccess ||
            SecIdentityCopyPrivateKey(identity, &privKey) != errSecSuccess) {
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
            if (err && errlen > 0) snprintf(err, errlen, "Failed to extract identity/key from .p12");
            return false;
        }

        certData = SecCertificateCopyData(cert);
        if (!parse_cert_der(CFDataGetBytePtr(certData), (size_t)CFDataGetLength(certData), &meta)) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
            if (err && errlen > 0) snprintf(err, errlen, "Failed to parse developer certificate");
            return false;
        }
    }

    /* Read Mach-O dylib */
    FILE *f = fopen(path, "r+b");
    if (!f) {
        if (has_identity) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
        }
        if (err && errlen > 0) snprintf(err, errlen, "Cannot open dylib: %s", path);
        return false;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < (long)sizeof(struct mach_header_64)) {
        fclose(f);
        if (has_identity) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
        }
        if (err && errlen > 0) snprintf(err, errlen, "File too small to be a Mach-O");
        return false;
    }

    /* Allocate buffer with margin for load commands and signature */
    size_t alloc_sz = (size_t)file_size + 131072;
    uint8_t *file_bytes = (uint8_t *)calloc(1, alloc_sz);
    if (!file_bytes || fread(file_bytes, 1, (size_t)file_size, f) != (size_t)file_size) {
        fclose(f);
        free(file_bytes);
        if (has_identity) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
        }
        if (err && errlen > 0) snprintf(err, errlen, "Failed to read dylib file");
        return false;
    }

    struct mach_header_64 *mh = (struct mach_header_64 *)file_bytes;
    if (mh->magic != MH_MAGIC_64) {
        fclose(f);
        free(file_bytes);
        if (has_identity) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
        }
        if (err && errlen > 0) snprintf(err, errlen, "Not a 64-bit arm64 Mach-O (magic 0x%x)", mh->magic);
        return false;
    }

    uint8_t *cmd_ptr = file_bytes + sizeof(struct mach_header_64);
    struct segment_command_64 *seg_text = NULL;
    struct segment_command_64 *seg_link = NULL;
    struct linkedit_data_command *cmd_cs = NULL;
    const char *dylib_id = NULL;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmd_ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) seg_text = seg;
            else if (strcmp(seg->segname, "__LINKEDIT") == 0) seg_link = seg;
        } else if (lc->cmd == LC_CODE_SIGNATURE) {
            cmd_cs = (struct linkedit_data_command *)lc;
        } else if (lc->cmd == LC_ID_DYLIB) {
            struct dylib_command *dc = (struct dylib_command *)lc;
            dylib_id = (const char *)lc + dc->dylib.name.offset;
            const char *slash = strrchr(dylib_id, '/');
            if (slash) dylib_id = slash + 1;
        }
        cmd_ptr += lc->cmdsize;
    }

    if (!seg_text || !seg_link) {
        fclose(f);
        free(file_bytes);
        if (has_identity) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
        }
        if (err && errlen > 0) snprintf(err, errlen, "Mach-O missing __TEXT or __LINKEDIT segment");
        return false;
    }

    if (!dylib_id || !dylib_id[0]) {
        const char *slash = strrchr(path, '/');
        dylib_id = slash ? slash + 1 : path;
    }

    /* Position signature: reuse existing LC_CODE_SIGNATURE offset, or append after current file */
    size_t dataoff = 0;
    if (cmd_cs) {
        dataoff = cmd_cs->dataoff;
    } else {
        dataoff = ((size_t)file_size + 15) & ~15ul;
        /* Insert new LC_CODE_SIGNATURE command */
        cmd_cs = (struct linkedit_data_command *)cmd_ptr;
        cmd_cs->cmd = LC_CODE_SIGNATURE;
        cmd_cs->cmdsize = sizeof(struct linkedit_data_command);
        cmd_cs->dataoff = (uint32_t)dataoff;
        cmd_cs->datasize = 0;
        mh->ncmds += 1;
        mh->sizeofcmds += sizeof(struct linkedit_data_command);
    }

    /* Zero pad any gap before dataoff */
    if (dataoff > (size_t)file_size) {
        memset(file_bytes + file_size, 0, dataoff - (size_t)file_size);
        file_size = (long)dataoff;
    }

    /* 1. Build Requirements blob */
    cs_buf req_buf;
    buf_init(&req_buf);
    if (has_identity) {
        size_t id_len = strlen(dylib_id);
        size_t id_pad = (4 - (id_len % 4)) % 4;
        uint32_t req_inner_len = 20 + (uint32_t)id_len + (uint32_t)id_pad;

        buf_put_u32_be(&req_buf, CSMAGIC_REQUIREMENTS);
        buf_put_u32_be(&req_buf, 12 + 8 + req_inner_len);
        buf_put_u32_be(&req_buf, 1);  /* count = 1 */
        buf_put_u32_be(&req_buf, 1);  /* type = kSecDesignatedRequirementType */
        buf_put_u32_be(&req_buf, 20); /* offset = 20 */

        buf_put_u32_be(&req_buf, CSMAGIC_REQUIREMENT);
        buf_put_u32_be(&req_buf, req_inner_len);
        buf_put_u32_be(&req_buf, 1);  /* kind = 1 */
        buf_put_u32_be(&req_buf, 2);  /* opIdent = 2 */
        buf_put_u32_be(&req_buf, (uint32_t)id_len);
        buf_put(&req_buf, dylib_id, id_len);
        for (size_t p = 0; p < id_pad; p++) buf_put_byte(&req_buf, 0);
    } else {
        /* Ad-hoc requirements vector */
        buf_put_u32_be(&req_buf, CSMAGIC_REQUIREMENTS);
        buf_put_u32_be(&req_buf, 12);
        buf_put_u32_be(&req_buf, 0);  /* count = 0 */
    }

    uint8_t req_sha256[32];
    CC_SHA256(req_buf.b, (CC_LONG)req_buf.n, req_sha256);

    /* Compute fixed lengths of CodeDirectory and SuperBlob to determine exact datasize */
    size_t n_pages = (dataoff + CS_PAGE_SIZE - 1) / CS_PAGE_SIZE;
    size_t cd_header_len = 88;
    size_t ident_len = strlen(dylib_id) + 1;
    size_t team_len = (has_identity && meta.team_id[0]) ? strlen(meta.team_id) + 1 : 0;
    size_t cd_pre_hashes = cd_header_len + ident_len + team_len;
    size_t cd_pad = (4 - (cd_pre_hashes % 4)) % 4;
    size_t cd_total_len = cd_pre_hashes + cd_pad + (2 + n_pages) * 32;

    size_t cms_len = 0;
    if (has_identity) {
        /* Probe CMS size to know exact final datasize */
        uint8_t dummy_cdhash[32] = {0};
        cs_buf cms_probe;
        if (!build_cms_signed_data(dummy_cdhash, 32, CFDataGetBytePtr(certData),
                                  (size_t)CFDataGetLength(certData), &meta, chain, privKey, &cms_probe)) {
            fclose(f);
            free(file_bytes);
            buf_free(&req_buf);
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
            if (err && errlen > 0) snprintf(err, errlen, "Failed to generate CMS signature probe");
            return false;
        }
        cms_len = cms_probe.n;
        buf_free(&cms_probe);
    }

    uint32_t slot_count = has_identity ? 3 : 2;
    size_t sb_hdr_size = 12 + slot_count * 8;
    uint32_t slot0_off = (uint32_t)sb_hdr_size;
    uint32_t slot1_off = (slot0_off + (uint32_t)cd_total_len + 7) & ~7u;
    uint32_t slot2_off = 0;
    uint32_t sb_total_len = 0;

    if (has_identity) {
        slot2_off = (slot1_off + (uint32_t)req_buf.n + 7) & ~7u;
        sb_total_len = slot2_off + 8 + (uint32_t)cms_len;
    } else {
        sb_total_len = slot1_off + (uint32_t)req_buf.n;
    }

    /*
     * CRITICAL: Update Mach-O header and __LINKEDIT in file_bytes BEFORE computing
     * page hashes, so that page 0 hash includes the updated load commands!
     */
    cmd_cs->dataoff = (uint32_t)dataoff;
    cmd_cs->datasize = sb_total_len;
    seg_link->filesize = (dataoff + sb_total_len) - seg_link->fileoff;
    seg_link->vmsize = (seg_link->filesize + 16383) & ~16383ul;

    /* Compute page hashes from final updated Mach-O file bytes */
    uint8_t *page_hashes = (uint8_t *)malloc(n_pages * 32);
    if (!page_hashes) {
        fclose(f);
        free(file_bytes);
        buf_free(&req_buf);
        if (has_identity) {
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
        }
        if (err && errlen > 0) snprintf(err, errlen, "Out of memory allocating page hashes");
        return false;
    }

    for (size_t i = 0; i < n_pages; i++) {
        size_t poff = i * CS_PAGE_SIZE;
        size_t plen = (poff + CS_PAGE_SIZE <= dataoff) ? CS_PAGE_SIZE : (dataoff - poff);
        CC_SHA256(file_bytes + poff, (CC_LONG)plen, page_hashes + i * 32);
    }

    /* Build CodeDirectory */
    cs_buf cd;
    buf_init(&cd);
    buf_put_u32_be(&cd, CSMAGIC_CODEDIRECTORY);
    size_t cd_len_pos = cd.n;
    buf_put_u32_be(&cd, 0); /* length placeholder */
    buf_put_u32_be(&cd, CS_SUPPORTSEXECSEG);
    buf_put_u32_be(&cd, has_identity ? 0 : CS_ADHOC);

    size_t hash_off_pos = cd.n;
    buf_put_u32_be(&cd, 0); /* hashOffset placeholder */
    size_t ident_off_pos = cd.n;
    buf_put_u32_be(&cd, 0); /* identOffset placeholder */

    buf_put_u32_be(&cd, 2); /* nSpecialSlots = 2 */
    buf_put_u32_be(&cd, (uint32_t)n_pages);
    buf_put_u32_be(&cd, (uint32_t)dataoff);
    buf_put_byte(&cd, 32);
    buf_put_byte(&cd, CS_HASHTYPE_SHA256);
    buf_put_byte(&cd, 0); /* platform */
    buf_put_byte(&cd, CS_PAGE_SIZE_LOG2);
    buf_put_u32_be(&cd, 0); /* spare2 */

    buf_put_u32_be(&cd, 0); /* scatterOffset */
    size_t team_off_pos = cd.n;
    buf_put_u32_be(&cd, 0); /* teamOffset placeholder */
    buf_put_u32_be(&cd, 0); /* spare3 */
    buf_put_u64_be(&cd, 0); /* codeLimit64 */
    buf_put_u64_be(&cd, seg_text->fileoff);
    buf_put_u64_be(&cd, seg_text->filesize);
    buf_put_u64_be(&cd, 0); /* execSegFlags */

    uint32_t ident_off = (uint32_t)cd.n;
    buf_put(&cd, dylib_id, strlen(dylib_id) + 1);

    uint32_t team_off = 0;
    if (has_identity && meta.team_id[0]) {
        team_off = (uint32_t)cd.n;
        buf_put(&cd, meta.team_id, strlen(meta.team_id) + 1);
    }

    while (cd.n % 4 != 0) buf_put_byte(&cd, 0);

    uint32_t hash_off = (uint32_t)cd.n + 2 * 32;
    buf_put(&cd, req_sha256, 32); /* Slot -2 */
    uint8_t zero_hash[32] = {0};
    buf_put(&cd, zero_hash, 32);  /* Slot -1 */

    buf_put(&cd, page_hashes, n_pages * 32);
    free(page_hashes);

    uint32_t be_cd_len = htonl((uint32_t)cd.n);
    memcpy(cd.b + cd_len_pos, &be_cd_len, 4);
    uint32_t be_hash_off = htonl(hash_off);
    memcpy(cd.b + hash_off_pos, &be_hash_off, 4);
    uint32_t be_ident_off = htonl(ident_off);
    memcpy(cd.b + ident_off_pos, &be_ident_off, 4);
    if (team_off) {
        uint32_t be_team_off = htonl(team_off);
        memcpy(cd.b + team_off_pos, &be_team_off, 4);
    }

    /* Compute CDHash (SHA-256 of the CodeDirectory) */
    uint8_t cdhash[32];
    CC_SHA256(cd.b, (CC_LONG)cd.n, cdhash);

    /* Build real CMS SignedData if signing with identity */
    cs_buf cms;
    buf_init(&cms);
    if (has_identity) {
        if (!build_cms_signed_data(cdhash, sizeof(cdhash),
                                  CFDataGetBytePtr(certData), (size_t)CFDataGetLength(certData),
                                  &meta, chain, privKey, &cms)) {
            fclose(f);
            free(file_bytes);
            buf_free(&cd);
            buf_free(&req_buf);
            CFRelease(certData);
            CFRelease(cert);
            CFRelease(privKey);
            CFRelease(items);
#if !TARGET_OS_IPHONE
            macos_cleanup_temp_keychain(kc, kc_path);
#endif
            if (err && errlen > 0) snprintf(err, errlen, "Failed to generate CMS signature");
            return false;
        }
    }

    /* Build SuperBlob */
    cs_buf sb;
    buf_init(&sb);
    buf_put_u32_be(&sb, CSMAGIC_EMBEDDED_SIGNATURE);
    size_t sb_len_pos = sb.n;
    buf_put_u32_be(&sb, 0); /* length placeholder */
    buf_put_u32_be(&sb, slot_count);

    buf_put_u32_be(&sb, CSSLOT_CODEDIRECTORY);
    buf_put_u32_be(&sb, slot0_off);
    buf_put_u32_be(&sb, CSSLOT_REQUIREMENTS);
    buf_put_u32_be(&sb, slot1_off);
    if (has_identity) {
        buf_put_u32_be(&sb, CSSLOT_SIGNATURESLOT);
        buf_put_u32_be(&sb, slot2_off);
    }

    /* Append CodeDirectory (Slot 0) */
    buf_put(&sb, cd.b, cd.n);
    while (sb.n < slot1_off) buf_put_byte(&sb, 0);

    /* Append Requirements (Slot 1) */
    buf_put(&sb, req_buf.b, req_buf.n);

    /* Append CMS BlobWrapper (Slot 2) */
    if (has_identity) {
        while (sb.n < slot2_off) buf_put_byte(&sb, 0);
        buf_put_u32_be(&sb, CSMAGIC_BLOBWRAPPER);
        buf_put_u32_be(&sb, (uint32_t)(8 + cms.n));
        buf_put(&sb, cms.b, cms.n);
    }

    uint32_t final_sb_len = (uint32_t)sb.n;
    uint32_t be_sb_len = htonl(final_sb_len);
    memcpy(sb.b + sb_len_pos, &be_sb_len, 4);

    /* Write updated dylib and signature back to disk */
    fseek(f, 0, SEEK_SET);
    fwrite(file_bytes, 1, dataoff, f);
    fwrite(sb.b, 1, sb.n, f);
    ftruncate(fileno(f), dataoff + sb.n);
    fclose(f);

    /* Clean up resources */
    buf_free(&cd);
    buf_free(&req_buf);
    buf_free(&cms);
    buf_free(&sb);
    free(file_bytes);

    if (has_identity) {
        CFRelease(certData);
        CFRelease(cert);
        CFRelease(privKey);
        CFRelease(items);
#if !TARGET_OS_IPHONE
        macos_cleanup_temp_keychain(kc, kc_path);
#endif
    }

    return true;
}

/* ------------------------------------------------------------ the app's own chain */

static uint32_t rd_be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

/* One BER element at p (within end): its tag, where its contents start and how long they are. Apple's signatures use indefinite
 * lengths (0x80 ... 00 00) for the outer structures, so an indefinite element's length is found by walking its children. */
static bool der_next(const uint8_t *p, const uint8_t *end, uint8_t *tag, const uint8_t **val, size_t *vlen)
{
    if (end - p < 2) return false;
    *tag = p[0];
    size_t n = p[1], h = 2;
    if (n == 0x80) {                                   /* indefinite: children until the 00 00 end marker */
        const uint8_t *c = p + 2;
        while (end - c >= 2 && !(c[0] == 0 && c[1] == 0)) {
            uint8_t t; const uint8_t *cv; size_t cn;
            if (!der_next(c, end, &t, &cv, &cn)) return false;
            c = cv + cn + (c[1] == 0x80 ? 2 : 0);     /* past the child (and its own end marker) */
        }
        if (end - c < 2) return false;
        *val = p + 2; *vlen = (size_t)(c - (p + 2));
        return true;
    }
    if (n & 0x80) {
        size_t k = n & 0x7f;
        if (k == 0 || k > 4 || (size_t)(end - p) < 2 + k) return false;
        n = 0;
        for (size_t i = 0; i < k; i++) n = n << 8 | p[2 + i];
        h += k;
    }
    if ((size_t)(end - p) < h + n) return false;
    *val = p + h; *vlen = n;
    return true;
}

/* The end of the element whose contents are v..v+n (an indefinite one also has its 00 00 marker) */
static const uint8_t *der_after(const uint8_t *elem, const uint8_t *v, size_t n) { return v + n + (elem[1] == 0x80 ? 2 : 0); }

int husk_codesign_chain_from_executable(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint8_t hdr[32];
    int found = 0;
    uint32_t dataoff = 0, datasize = 0;
    if (fread(hdr, 1, sizeof(hdr), f) == sizeof(hdr) && *(uint32_t *)hdr == 0xfeedfacfu) {   /* a thin 64-bit Mach-O */
        uint32_t ncmds = *(uint32_t *)(hdr + 16), sizeofcmds = *(uint32_t *)(hdr + 20);
        uint8_t *cmds = malloc(sizeofcmds);
        if (cmds && fread(cmds, 1, sizeofcmds, f) == sizeofcmds) {
            for (uint32_t i = 0, at = 0; i < ncmds && at + 8 <= sizeofcmds; i++) {
                uint32_t cmd = *(uint32_t *)(cmds + at), size = *(uint32_t *)(cmds + at + 4);
                if (cmd == 0x1d && at + 16 <= sizeofcmds) { dataoff = *(uint32_t *)(cmds + at + 8); datasize = *(uint32_t *)(cmds + at + 12); }
                if (size < 8) break;
                at += size;
            }
        }
        free(cmds);
    }
    uint8_t *sig = datasize && datasize < (16u << 20) ? malloc(datasize) : NULL;
    if (sig && fseek(f, dataoff, SEEK_SET) == 0 && fread(sig, 1, datasize, f) == datasize && rd_be32(sig) == 0xfade0cc0u) {
        uint32_t count = rd_be32(sig + 8);
        for (uint32_t i = 0; i < count && 12 + 8 * (size_t)(i + 1) <= datasize; i++) {
            uint32_t type = rd_be32(sig + 12 + 8 * i), off = rd_be32(sig + 16 + 8 * i);
            if (type != 0x10000 || (size_t)off + 8 > datasize || rd_be32(sig + off) != 0xfade0b01u) continue;
            uint32_t blen = rd_be32(sig + off + 4);
            if (blen < 8 || (size_t)off + blen > datasize) continue;
            /* ContentInfo { contentType, [0] { SignedData { version, digestAlgorithms, encapContentInfo, [0] certificates ... } } } */
            const uint8_t *p = sig + off + 8, *end = sig + off + blen, *v; size_t n; uint8_t tag;
            if (!der_next(p, end, &tag, &v, &n) || tag != 0x30) continue;            /* ContentInfo */
            const uint8_t *q = v, *qe = v + n;
            if (!der_next(q, qe, &tag, &v, &n) || tag != 0x06) continue;             /* contentType */
            q = der_after(q, v, n);
            if (!der_next(q, qe, &tag, &v, &n) || tag != 0xa0) continue;             /* [0] */
            if (!der_next(v, v + n, &tag, &v, &n) || tag != 0x30) continue;          /* SignedData */
            q = v; qe = v + n;
            for (int field = 0; q < qe && der_next(q, qe, &tag, &v, &n); field++, q = der_after(q, v, n)) {
                if (tag != 0xa0 || field < 3) continue;                                 /* [0] certificates, after the first three */
                for (const uint8_t *c = v, *ce = v + n; c < ce; ) {
                    const uint8_t *cv; size_t cn;
                    if (!der_next(c, ce, &tag, &cv, &cn)) break;
                    size_t whole = (size_t)(der_after(c, cv, cn) - c);
                    if (tag == 0x30 && g_nchain < CHAIN_MAX && !chain_has(c, whole) && (g_chain[g_nchain].der = malloc(whole))) {
                        memcpy(g_chain[g_nchain].der, c, whole);
                        g_chain[g_nchain++].len = whole;
                        found++;
                    }
                    c = der_after(c, cv, cn);
                }
                break;
            }
        }
    }
    free(sig);
    fclose(f);
    return found;
}
