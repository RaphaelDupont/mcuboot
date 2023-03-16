/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2018-2019 JUUL Labs
 * Copyright (c) 2019-2021 Arm Limited
 */

#include "encrypted_priv.h"

#if defined(MCUBOOT_ENC_IMAGES) && defined(MCUBOOT_ENCRYPT_RSA)

#include "mbedtls/rsa.h"
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#include "rsa_alt_helpers.h"
#else
#include "mbedtls/rsa_internal.h"
#endif
#include "mbedtls/asn1.h"

static int
parse_rsa_enckey(mbedtls_rsa_context *ctx, uint8_t **p, uint8_t *end)
{
    size_t len;

    if (mbedtls_asn1_get_tag(p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return -1;
    }

    if (*p + len != end) {
        return -2;
    }

    /* Non-optional fields. */
    if ( /* version */
        mbedtls_asn1_get_int(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(ver)) != 0 ||
         /* public modulus */
        mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(N)) != 0 ||
         /* public exponent */
        mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(E)) != 0 ||
         /* private exponent */
        mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(D)) != 0 ||
         /* primes */
        mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(P)) != 0 ||
        mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(Q)) != 0) {

        return -3;
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    /*
     * DP/DQ/QP are only used inside mbedTLS if it was built with the
     * Chinese Remainder Theorem enabled (default). In case it is disabled
     * we parse, or if not available, we calculate those values.
     */
    if (*p < end) {
        if ( /* d mod (p-1) and d mod (q-1) */
            mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(DP)) != 0 ||
            mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(DQ)) != 0 ||
             /* q ^ (-1) mod p */
            mbedtls_asn1_get_mpi(p, end, &ctx->MBEDTLS_CONTEXT_MEMBER(QP)) != 0) {

            return -4;
        }
    } else {
        if (mbedtls_rsa_deduce_crt(&ctx->MBEDTLS_CONTEXT_MEMBER(P),
                                   &ctx->MBEDTLS_CONTEXT_MEMBER(Q),
                                   &ctx->MBEDTLS_CONTEXT_MEMBER(D),
                                   &ctx->MBEDTLS_CONTEXT_MEMBER(DP),
                                   &ctx->MBEDTLS_CONTEXT_MEMBER(DQ),
                                   &ctx->MBEDTLS_CONTEXT_MEMBER(QP)) != 0) {
            return -5;
        }
    }
#endif

    ctx->MBEDTLS_CONTEXT_MEMBER(len) = mbedtls_mpi_size(&ctx->MBEDTLS_CONTEXT_MEMBER(N));

    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        return -6;
    }

    return 0;
}

/*
 * Decrypt an encryption key TLV.
 *
 * @param buf An encryption TLV read from flash (build time fixed length)
 * @param enckey An AES-128 or AES-256 key sized buffer to store to plain key.
 */
int
boot_enc_decrypt(const uint8_t *buf, uint8_t *enckey)
{
    mbedtls_rsa_context rsa;
    uint8_t *cp;
    uint8_t *cpend;
    size_t olen;

    int rc = -1;

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_rsa_init(&rsa);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#else
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#endif
    cp = (uint8_t *)bootutil_enc_key.key;
    cpend = cp + *bootutil_enc_key.len;

    rc = parse_rsa_enckey(&rsa, &cp, cpend);
    if (rc) {
        mbedtls_rsa_free(&rsa);
        return rc;
    }
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    rc = mbedtls_rsa_rsaes_oaep_decrypt(&rsa, fake_rng, NULL,
            NULL, 0, &olen, buf, enckey, BOOT_ENC_KEY_SIZE);
#else
    rc = mbedtls_rsa_rsaes_oaep_decrypt(&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
            NULL, 0, &olen, buf, enckey, BOOT_ENC_KEY_SIZE);
#endif
    mbedtls_rsa_free(&rsa);

    return rc;
}

#endif /* MCUBOOT_ENC_IMAGES && MCUBOOT_ENCRYPT_RSA */
