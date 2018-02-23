#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "cp_crypto.h"

commpact_status_t cp_ecc256_open_context(void **p_ecc_handle) {
  if (p_ecc_handle == NULL) {
    return CP_ERROR;
  }

  commpact_status_t retval = CP_SUCCESS;
  CLEAR_OPENSSL_ERROR_QUEUE;

  /* construct a curve p-256 */
  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (NULL == ec_group) {
    GET_LAST_OPENSSL_ERROR;
    retval = CP_ERROR;
  } else {
    *p_ecc_handle = (void *)ec_group;
  }
  return retval;
}

commpact_status_t cp_ecc256_close_context(void *ecc_handle) {
  if (ecc_handle == NULL) {
    return CP_ERROR;
  }

  EC_GROUP_free((EC_GROUP *)ecc_handle);

  return CP_SUCCESS;
}

commpact_status_t cp_ecc256_create_key_pair(cp_ec256_private_t *p_private,
                                            cp_ec256_public_t *p_public,
                                            void *ecc_handle) {
  if ((ecc_handle == NULL) || (p_private == NULL) || (p_public == NULL)) {
    return CP_ERROR;
  }

  EC_GROUP *ec_group = (EC_GROUP *)ecc_handle;
  EC_KEY *ec_key = NULL;
  BIGNUM *pub_k_x = NULL;
  BIGNUM *pub_k_y = NULL;
  const EC_POINT *public_k = NULL;
  const BIGNUM *private_k = NULL;
  commpact_status_t ret = CP_ERROR;

  CLEAR_OPENSSL_ERROR_QUEUE;

  do {
    // create new EC key
    //
    ec_key = EC_KEY_new();
    if (NULL == ec_key) {
      ret = CP_ERROR;
      break;
    }

    // set key's group (curve)
    //
    if (0 == EC_KEY_set_group(ec_key, ec_group)) {
      break;
    }

    // generate key pair, based on the curve set
    //
    if (0 == EC_KEY_generate_key(ec_key)) {
      break;
    }

    pub_k_x = BN_new();
    pub_k_y = BN_new();
    if (NULL == pub_k_x || NULL == pub_k_y) {
      ret = CP_ERROR;
      break;
    }

    // This OPENSSL API doesn't validate user's parameters
    // get public and private keys
    //
    public_k = EC_KEY_get0_public_key(ec_key);
    if (NULL == ec_key) {
      break;
    }
    private_k = EC_KEY_get0_private_key(ec_key);
    if (NULL == ec_key) {
      break;
    }

    // extract two BNs representing the public key
    //
    if (!EC_POINT_get_affine_coordinates_GFp(ec_group, public_k, pub_k_x,
                                             pub_k_y, NULL)) {
      break;
    }

    // convert private key BN to little-endian unsigned char form
    //
    if (-1 == BN_bn2lebinpad(private_k, (unsigned char *)p_private,
                             CP_ECP256_KEY_SIZE)) {
      break;
    }

    // convert public key BN to little-endian unsigned char form
    //
    if (-1 == BN_bn2lebinpad(pub_k_x, (unsigned char *)p_public->gx,
                             CP_ECP256_KEY_SIZE)) {
      break;
    }
    // convert public key BN to little-endian unsigned char form
    //
    if (-1 == BN_bn2lebinpad(pub_k_y, (unsigned char *)p_public->gy,
                             CP_ECP256_KEY_SIZE)) {
      break;
    }

    ret = CP_SUCCESS;
  } while (0);

  if (CP_SUCCESS != ret) {
    GET_LAST_OPENSSL_ERROR;
    // in case of error, clear output buffers
    //
    memset_s(p_private, sizeof(p_private), 0, sizeof(p_private));
    memset_s(p_public->gx, sizeof(p_public->gx), 0, sizeof(p_public->gx));
    memset_s(p_public->gy, sizeof(p_public->gy), 0, sizeof(p_public->gy));
  }

  // free temp data
  //
  EC_KEY_free(ec_key);
  BN_clear_free(pub_k_x);
  BN_clear_free(pub_k_y);

  return ret;
}

commpact_status_t cp_ecdsa_sign(const uint8_t *p_data, uint32_t data_size,
                                cp_ec256_private_t *p_private,
                                cp_ec256_signature_t *p_signature,
                                void *ecc_handle) {
  if ((ecc_handle == NULL) || (p_private == NULL) || (p_signature == NULL) ||
      (p_data == NULL) || (data_size < 1)) {
    return CP_ERROR;
  }

  EC_KEY *private_key = NULL;
  BIGNUM *bn_priv = NULL;
  ECDSA_SIG *ecdsa_sig = NULL;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
  unsigned char digest[CP_SHA256_HASH_SIZE] = {0};
  int written_bytes = 0;
  int sig_size = 0;
  int max_sig_size = 0;
  commpact_status_t retval = CP_ERROR;
  CLEAR_OPENSSL_ERROR_QUEUE;

  do {
    // converts the r value of private key, represented as positive integer in
    // little-endian into a BIGNUM
    //
    bn_priv =
        BN_lebin2bn((unsigned char *)p_private->r, sizeof(p_private->r), 0);
    if (NULL == bn_priv) {
      break;
    }

    // create empty ecc key
    //
    private_key = EC_KEY_new();
    if (NULL == private_key) {
      retval = CP_ERROR;
      break;
    }

    // sets ecc key group (set curve)
    //
    if (1 != EC_KEY_set_group(private_key, (EC_GROUP *)ecc_handle)) {
      break;
    }

    // uses bn_priv to set the ecc private key
    //
    if (1 != EC_KEY_set_private_key(private_key, bn_priv)) {
      break;
    }

    /* generates digest of p_data */
    if (NULL == SHA256((const unsigned char *)p_data, data_size,
                       (unsigned char *)digest)) {
      break;
    }

    // computes a digital signature of the CP_SHA256_HASH_SIZE bytes hash value
    // dgst using the private EC key private_key.
    // the signature is returned as a newly allocated ECDSA_SIG structure.
    //
    ecdsa_sig = ECDSA_do_sign(digest, CP_SHA256_HASH_SIZE, private_key);
    if (NULL == ecdsa_sig) {
      break;
    }

    // returns internal pointers the r and s values contained in ecdsa_sig.
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);

    // converts the r BIGNUM of the signature to little endian buffer, bounded
    // with the len of out buffer
    //
    written_bytes =
        BN_bn2lebinpad(r, (unsigned char *)p_signature->x, CP_ECP256_KEY_SIZE);
    if (0 >= written_bytes) {
      break;
    }
    sig_size = written_bytes;

    // converts the s BIGNUM of the signature to little endian buffer, bounded
    // with the len of out buffer
    //
    written_bytes =
        BN_bn2lebinpad(s, (unsigned char *)p_signature->y, CP_ECP256_KEY_SIZE);
    if (0 >= written_bytes) {
      break;
    }
    sig_size += written_bytes;

    // returns the maximum length of a DER encoded ECDSA signature created with
    // the private EC key.
    //
    max_sig_size = ECDSA_size(private_key);
    if (max_sig_size <= 0) {
      break;
    }

    // checks if the signature size not larger than the max len of valid
    // signature
    // this check if done for validity, not for overflow.
    //
    if (sig_size > max_sig_size) {
      break;
    }

    retval = CP_SUCCESS;
  } while (0);

  if (CP_SUCCESS != retval) {
    GET_LAST_OPENSSL_ERROR;
  }

  if (bn_priv)
    BN_clear_free(bn_priv);
  if (ecdsa_sig)
    ECDSA_SIG_free(ecdsa_sig);
  if (private_key)
    EC_KEY_free(private_key);

  return retval;
}

commpact_status_t cp_ecdsa_verify(const uint8_t *p_data, uint32_t data_size,
                                  const cp_ec256_public_t *p_public,
                                  cp_ec256_signature_t *p_signature,
                                  uint8_t *p_result, void *ecc_handle) {
  if ((ecc_handle == NULL) || (p_public == NULL) || (p_signature == NULL) ||
      (p_data == NULL) || (data_size < 1) || (p_result == NULL)) {
    return CP_ERROR;
  }

  EC_KEY *public_key = NULL;
  BIGNUM *bn_pub_x = NULL;
  BIGNUM *bn_pub_y = NULL;
  BIGNUM *bn_r = NULL;
  BIGNUM *bn_s = NULL;
  BIGNUM *prev_bn_r = NULL;
  BIGNUM *prev_bn_s = NULL;
  EC_POINT *public_point = NULL;
  ECDSA_SIG *ecdsa_sig = NULL;
  unsigned char digest[CP_SHA256_HASH_SIZE] = {0};
  commpact_status_t retval = CP_ERROR;
  int valid = 0;

  *p_result = CP_EC_INVALID_SIGNATURE;

  CLEAR_OPENSSL_ERROR_QUEUE;

  do {
    // converts the x value of public key, represented as positive integer in
    // little-endian into a BIGNUM
    //
    bn_pub_x =
        BN_lebin2bn((unsigned char *)p_public->gx, sizeof(p_public->gx), 0);
    if (NULL == bn_pub_x) {
      break;
    }

    // converts the y value of public key, represented as positive integer in
    // little-endian into a BIGNUM
    //
    bn_pub_y =
        BN_lebin2bn((unsigned char *)p_public->gy, sizeof(p_public->gy), 0);
    if (NULL == bn_pub_y) {
      break;
    }

    // converts the x value of the signature, represented as positive integer in
    // little-endian into a BIGNUM
    //
    bn_r =
        BN_lebin2bn((unsigned char *)p_signature->x, sizeof(p_signature->x), 0);
    if (NULL == bn_r) {
      break;
    }

    // converts the y value of the signature, represented as positive integer in
    // little-endian into a BIGNUM
    //
    bn_s =
        BN_lebin2bn((unsigned char *)p_signature->y, sizeof(p_signature->y), 0);
    if (NULL == bn_s) {
      break;
    }

    // creates new point and assigned the group object that the point relates to
    //
    public_point = EC_POINT_new((EC_GROUP *)ecc_handle);
    if (public_point == NULL) {
      retval = CP_ERROR;
      break;
    }

    // sets point based on public key's x,y coordinates
    //
    if (1 != EC_POINT_set_affine_coordinates_GFp((EC_GROUP *)ecc_handle,
                                                 public_point, bn_pub_x,
                                                 bn_pub_y, NULL)) {
      break;
    }

    // check point if the point is on curve
    //
    if (1 != EC_POINT_is_on_curve((EC_GROUP *)ecc_handle, public_point, NULL)) {
      break;
    }

    // create empty ecc key
    //
    public_key = EC_KEY_new();
    if (NULL == public_key) {
      retval = CP_ERROR;
      break;
    }

    // sets ecc key group (set curve)
    //
    if (1 != EC_KEY_set_group(public_key, (EC_GROUP *)ecc_handle)) {
      break;
    }

    // uses the created point to set the public key value
    //
    if (1 != EC_KEY_set_public_key(public_key, public_point)) {
      break;
    }

    /* generates digest of p_data */
    if (NULL == SHA256((const unsigned char *)p_data, data_size,
                       (unsigned char *)digest)) {
      break;
    }

    // allocates a new ECDSA_SIG structure (note: this function also allocates
    // the BIGNUMs) and initialize it
    //
    ecdsa_sig = ECDSA_SIG_new();
    if (NULL == ecdsa_sig) {
      retval = CP_ERROR;
      break;
    }

    // free internal allocated BIGBNUMs
    ECDSA_SIG_get0(ecdsa_sig, (const BIGNUM **)&prev_bn_r,
                   (const BIGNUM **)&prev_bn_s);
    if (prev_bn_r)
      BN_clear_free(prev_bn_r);
    if (prev_bn_s)
      BN_clear_free(prev_bn_s);

    // setes the r and s values of ecdsa_sig
    // calling this function transfers the memory management of the values to
    // the ECDSA_SIG object,
    // and therefore the values that have been passed in should not be freed
    // directly after this function has been called
    //
    if (1 != ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s)) {
      ECDSA_SIG_free(ecdsa_sig);
      ecdsa_sig = NULL;
      break;
    }
    // verifies that the signature ecdsa_sig is a valid ECDSA signature of the
    // hash value digest of size CP_SHA256_HASH_SIZE using the public key
    // public_key
    //
    valid = ECDSA_do_verify(digest, CP_SHA256_HASH_SIZE, ecdsa_sig, public_key);
    if (-1 == valid) {
      break;
    }

    // sets the p_result based on ECDSA_do_verify result
    //
    if (valid) {
      *p_result = CP_EC_VALID;
    }

    retval = CP_SUCCESS;
  } while (0);

  if (CP_SUCCESS != retval) {
    GET_LAST_OPENSSL_ERROR;
  }

  if (bn_pub_x)
    BN_clear_free(bn_pub_x);
  if (bn_pub_y)
    BN_clear_free(bn_pub_y);
  if (public_point)
    EC_POINT_clear_free(public_point);
  if (ecdsa_sig) {
    ECDSA_SIG_free(ecdsa_sig);
    bn_r = NULL;
    bn_s = NULL;
  }
  if (public_key)
    EC_KEY_free(public_key);
  if (bn_r)
    BN_clear_free(bn_r);
  if (bn_s)
    BN_clear_free(bn_s);

  return retval;
}
