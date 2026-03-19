/* _pystandalone module */
/* Author: Erik Schamper <1254028+Schamper@users.noreply.github.com> */

#include "Python.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// LibreSSL doesn't define EVP_CTRL_AEAD_GET_TAG, but it's the same value
#ifndef EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_AEAD_GET_TAG   EVP_CTRL_GCM_GET_TAG
#define EVP_CTRL_AEAD_SET_TAG   EVP_CTRL_GCM_SET_TAG
#endif

// Some compatibility defines for CPython < 3.11

#ifndef _PyCFunction_CAST
#define _Py_CAST(type, expr) ((type)(expr))
#define _PyCFunction_CAST(func) \
    _Py_CAST(PyCFunction, _Py_CAST(void(*)(void), (func)))
#endif

#ifndef Py_TPFLAGS_DISALLOW_INSTANTIATION
#define Py_TPFLAGS_DISALLOW_INSTANTIATION (1UL << 7)
#endif

#ifndef Py_TPFLAGS_IMMUTABLETYPE
#define Py_TPFLAGS_IMMUTABLETYPE (1UL << 8)
#endif

/* Internal module state */

typedef struct {
    PyTypeObject *Cipher_type;
    PyTypeObject *PublicKey_type;
} _pystandalone_state;

static inline _pystandalone_state*
get_pystandalone_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (_pystandalone_state *)state;
}

/* Class object definitions */

#define CIPHER_MODE_NONE        -1
#define CIPHER_MODE_DECRYPT      0
#define CIPHER_MODE_ENCRYPT      1

#define CIPHER_STATE_CLEAR      -1
#define CIPHER_STATE_NONE        0
#define CIPHER_STATE_INIT        1
#define CIPHER_STATE_FINAL       2

typedef struct {
    PyObject_HEAD
    EVP_CIPHER_CTX      *ctx;   /* OpenSSL cipher context */
    unsigned char        key[EVP_MAX_KEY_LENGTH];
    unsigned char        iv[EVP_MAX_IV_LENGTH];
    int                  enc;
    int                  state;
} Cipher;

typedef struct {
    PyObject_HEAD
    EVP_PKEY_CTX        *ctx;   /* OpenSSL pkey context */
} PublicKey;

/*[clinic input]
module _pystandalone
class _pystandalone.Cipher "Cipher *" "&Cipher_type"
class _pystandalone.PublicKey "PublicKey *" "&PublicKey_type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=a745ffb6f8be8095]*/

#include "clinic/_pystandalone.c.h"

/* Utility functions */

/* Set the Python exception from OpenSSL error information. */
static void
_set_exception(PyObject *exc)
{
    unsigned long errcode;
    const char *lib, *func, *reason;

    errcode = ERR_peek_last_error();
    if (!errcode) {
        PyErr_SetString(exc, "unknown reasons");
        return;
    }
    ERR_clear_error();

    lib = ERR_lib_error_string(errcode);
    func = ERR_func_error_string(errcode);
    reason = ERR_reason_error_string(errcode);

    if (lib && func) {
        PyErr_Format(exc, "[%s: %s] %s", lib, func, reason);
    }
    else if (lib) {
        PyErr_Format(exc, "[%s] %s", lib, reason);
    }
    else {
        PyErr_SetString(exc, reason);
    }
    return;
}

/* Get the name of a NID as a Python string. */
static PyObject*
py_nid_to_name(int nid)
{
    const char *name = OBJ_nid2ln(nid);

    if (name == NULL) {
        name = OBJ_nid2sn(nid);
    }

    return PyUnicode_FromString(name);
}

/* Get the name of an EVP_CIPHER as a Python string. */
static PyObject*
py_cipher_name(const EVP_CIPHER *ctx)
{
    int nid = EVP_CIPHER_nid(ctx);
    return py_nid_to_name(nid);
}

/* Load a PEM encoded RSA public key */
static EVP_PKEY*
load_pem_rsa_public_key(Py_buffer *key)
{
    BIO *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_mem_buf(key->buf, key->len);
    if (bio == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        _set_exception(PyExc_ValueError);
        return NULL;
    }

    return pkey;
}

/* Load a DER encoded RSA public key */
static EVP_PKEY*
load_der_rsa_public_key(Py_buffer *key)
{
    RSA *rsa;
    EVP_PKEY *pkey;

    rsa = d2i_RSA_PUBKEY(NULL, (const unsigned char**)&key->buf, key->len);
    if (rsa == NULL) {
        _set_exception(PyExc_ValueError);
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        PyErr_NoMemory();
        RSA_free(rsa);
        return NULL;
    }

    if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
        _set_exception(PyExc_ValueError);
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return NULL;
    }

    RSA_free(rsa);

    return pkey;
}

/* Load a PEM or DER encoded public key. */
static EVP_PKEY*
load_rsa_public_key(Py_buffer *key)
{
    if (key->len > 60 && memcmp(key->buf, "-----", 5) == 0) {
        // Probably PEM
        return load_pem_rsa_public_key(key);
    }
    else {
        // Probably DER
        return load_der_rsa_public_key(key);
    }
}

/* Cipher class */

/* Internal methods for Cipher object */

/* Create a new Cipher object from a given EVP_CIPHER, key and iv. */
static Cipher*
_Cipher_new(PyObject *module, const EVP_CIPHER *cipher, Py_buffer *key, Py_buffer *iv)
{
    PyTypeObject *type = get_pystandalone_state(module)->Cipher_type;
    Cipher *self;
    int expected_key_length, expected_iv_length;

    if (!cipher) {
        PyErr_SetString(PyExc_ValueError, "unsupported cipher type");
        return NULL;
    }

    if (EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE) {
        PyErr_SetString(PyExc_ValueError, "CCM mode is currently unsupported");
        return NULL;
    }

    if ((expected_key_length = EVP_CIPHER_key_length(cipher)) != key->len){
        PyErr_Format(PyExc_ValueError, "key must be %d bytes", expected_key_length);
        return NULL;
    }

    if ((expected_iv_length = EVP_CIPHER_iv_length(cipher)) != iv->len) {
        PyErr_Format(PyExc_ValueError, "iv must be %d bytes", expected_iv_length);
        return NULL;
    }

    self = PyObject_New(Cipher, type);
    if (self == NULL) {
        return NULL;
    }

    self->ctx = EVP_CIPHER_CTX_new();
    if (self->ctx == NULL) {
        Py_DECREF(self);
        PyErr_NoMemory();
        return NULL;
    }

    self->enc = CIPHER_MODE_NONE;
    self->state = CIPHER_STATE_NONE;
    memcpy(self->key, key->buf, key->len);
    memcpy(self->iv, iv->buf, iv->len);

    /* initialize the context with the cipher type only; key schedule is
     * deferred to _Cipher_init when the enc direction is known */
    if (!EVP_CipherInit_ex(self->ctx, cipher, NULL, NULL, NULL, -1)) {
        _set_exception(PyExc_ValueError);
        Py_DECREF(self);
        return NULL;
    }

    /* disable padding so the caller must handle it */
    EVP_CIPHER_CTX_set_padding(self->ctx, 0);

    return self;
}

/* Clean a cipher object. */
static void
_Cipher_clean(Cipher *self)
{
    EVP_CIPHER_CTX_cleanup(self->ctx);
    OPENSSL_cleanse(self->key, sizeof(self->key));
    OPENSSL_cleanse(self->iv, sizeof(self->iv));
    self->enc = CIPHER_MODE_NONE;
    self->state = CIPHER_STATE_CLEAR;
}

/* Initialize a cipher object with the given mode (encrypt or decrypt). */
static int
_Cipher_init(Cipher *self, int enc)
{
    if (self->state != CIPHER_STATE_NONE) {
        if (self->state == CIPHER_STATE_CLEAR) {
            PyErr_SetString(PyExc_TypeError, "cipher object already cleaned");
            return -1;
        }
        if (self->state == CIPHER_STATE_FINAL) {
            PyErr_SetString(PyExc_TypeError, "cipher object already finalized");
            return -1;
        }
        if (self->enc != enc) {
            PyErr_Format(PyExc_TypeError, "cipher object already initialised for %s", enc ? "encryption" : "decryption");
            return -1;
        }
        return 0;
    }

    self->enc = enc;
    self->state = CIPHER_STATE_INIT;

    if (!EVP_CipherInit_ex(self->ctx, NULL, NULL, self->key, self->iv, enc)) {
        _set_exception(PyExc_ValueError);
        _Cipher_clean(self);
        return -1;
    }

    OPENSSL_cleanse(self->key, sizeof(self->key));
    OPENSSL_cleanse(self->iv, sizeof(self->iv));

    return 0;
}

/* Perform an encrypt or decrypt operation on the given data. */
static PyObject *
_Cipher_crypt(Cipher *self, Py_buffer *data, int enc)
{
    PyObject *buf;
    int out_len, block_size;
    unsigned char *out_buf;

    if (_Cipher_init(self, enc) == -1) {
        return NULL;
    }

    /* force the caller to do the proper padding */
    block_size = EVP_CIPHER_CTX_block_size(self->ctx);
    if (data->len % block_size != 0) {
        PyErr_Format(PyExc_ValueError, "data must be padded to block size (%d bytes for this cipher)", block_size);
        return NULL;
    }

    /* data is already block aligned, can use an output buffer of the same size */
    buf = PyBytes_FromStringAndSize(NULL, data->len);
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    out_buf = (unsigned char *)PyBytes_AS_STRING(buf);
    if (!EVP_CipherUpdate(self->ctx, out_buf, &out_len, data->buf, data->len)) {
        _set_exception(PyExc_ValueError);
        _Cipher_clean(self);
        Py_DECREF(buf);
        return NULL;
    }

    return buf;
}

/* Update the AD (Additional Data) for AEAD cipher objects. */
static PyObject *
_Cipher_update_ad(Cipher *self, Py_buffer *data)
{
    int out_len;

    if (!(EVP_CIPHER_CTX_flags(self->ctx) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        PyErr_SetString(PyExc_TypeError, "specifying additional data is only allowed on AEAD ciphers");
        return NULL;
    }

    if (self->enc != CIPHER_MODE_NONE && self->state != CIPHER_STATE_NONE) {
        PyErr_SetString(PyExc_TypeError, "specifying additional data is only allowed on non-initialized ciphers");
        return NULL;
    }

    if (!EVP_CipherUpdate(self->ctx, NULL, &out_len, data->buf, data->len)) {
        _set_exception(PyExc_ValueError);
        return NULL;
    }

    Py_RETURN_NONE;
}

/* Get the tag for AEAD cipher objects. */
static PyObject *
_Cipher_get_tag(Cipher *self)
{
    PyObject *buf;
    int final_len;
    unsigned char final[1];
    unsigned char *out_buf;

    if (!(EVP_CIPHER_CTX_flags(self->ctx) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        PyErr_SetString(PyExc_TypeError, "getting a tag is only allowed on AEAD ciphers");
        return NULL;
    }

    if (self->enc != CIPHER_MODE_ENCRYPT) {
        PyErr_SetString(PyExc_TypeError, "getting a tag is only allowed on encryption ciphers");
        return NULL;
    }

    if (self->state != CIPHER_STATE_INIT && self->state != CIPHER_STATE_FINAL) {
        PyErr_SetString(PyExc_TypeError, "getting a tag is only allowed on initialized or finalized ciphers");
        return NULL;
    }

    if (self->state != CIPHER_STATE_FINAL) {
        /* the cipher first needs to be finalized */
        self->state = CIPHER_STATE_FINAL;
        if (!EVP_CipherFinal_ex(self->ctx, final, &final_len)) {
            _set_exception(PyExc_ValueError);
            _Cipher_clean(self);
            return NULL;
        }
    }

    buf = PyBytes_FromStringAndSize(NULL, 16);
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    out_buf = (unsigned char *)PyBytes_AS_STRING(buf);
    if (!EVP_CIPHER_CTX_ctrl(self->ctx, EVP_CTRL_AEAD_GET_TAG, 16, out_buf)) {
        _set_exception(PyExc_ValueError);
        _Cipher_clean(self);
        Py_DECREF(buf);
        return NULL;
    }

    return buf;
}

/* Verify the tag for AEAD cipher objects. */
static PyObject *
_Cipher_verify_tag(Cipher *self, Py_buffer *tag)
{
    int final_len;
    unsigned char final[1];

    if (!(EVP_CIPHER_CTX_flags(self->ctx) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        PyErr_SetString(PyExc_TypeError, "verifying a tag is only allowed on AEAD ciphers");
        return NULL;
    }

    if (self->enc != CIPHER_MODE_DECRYPT) {
        PyErr_SetString(PyExc_TypeError, "verifying a tag is only allowed on decryption ciphers");
        return NULL;
    }

    if (self->state != CIPHER_STATE_INIT) {
        PyErr_SetString(PyExc_TypeError, "verifying a tag is only allowed on initialized ciphers");
        return NULL;
    }

    if (tag->len != 16) {
        PyErr_SetString(PyExc_ValueError, "tag must be 16 bytes");
        return NULL;
    }

    if (!EVP_CIPHER_CTX_ctrl(self->ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag->buf)) {
        _set_exception(PyExc_ValueError);
        _Cipher_clean(self);
        return NULL;
    }

    self->state = CIPHER_STATE_FINAL;
    if (!EVP_CipherFinal_ex(self->ctx, final, &final_len)) {
        PyErr_SetString(PyExc_ValueError, "tag verification failed");
        return NULL;
    }

    Py_RETURN_NONE;
}

/* Public methods for Cipher object */

/*[clinic input]
_pystandalone.Cipher.encrypt

    data: Py_buffer

Return the encrypted data as a bytes object.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_encrypt_impl(Cipher *self, Py_buffer *data)
/*[clinic end generated code: output=905ce94ccf6e0082 input=17d62fae407625b9]*/
{
    return _Cipher_crypt(self, data, CIPHER_MODE_ENCRYPT);
}

/*[clinic input]
_pystandalone.Cipher.encrypt_and_digest

    data: Py_buffer

Return the encrypted data and digest as a tuple of two byte objects.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_encrypt_and_digest_impl(Cipher *self, Py_buffer *data)
/*[clinic end generated code: output=353713949361b05c input=1cf53ffdfdb2c8ef]*/
{
    PyObject *buf, *digest;

    buf = _Cipher_crypt(self, data, CIPHER_MODE_ENCRYPT);
    if (buf == NULL) {
        return NULL;
    }

    digest = _Cipher_get_tag(self);
    if (digest == NULL) {
        Py_DECREF(buf);
        return NULL;
    }

    return PyTuple_Pack(2, buf, digest);
}

/*[clinic input]
_pystandalone.Cipher.decrypt

    data: Py_buffer

Return the decrypted data as a bytes object.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_decrypt_impl(Cipher *self, Py_buffer *data)
/*[clinic end generated code: output=dd94f41ddbeaccf7 input=363abf129f94df00]*/
{
    return _Cipher_crypt(self, data, CIPHER_MODE_DECRYPT);
}

/*[clinic input]
_pystandalone.Cipher.decrypt_and_verify

    data: Py_buffer
    tag: Py_buffer

Verify the decrypted data and return it as a bytes object.

Raises an exception if the tag verification fails.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_decrypt_and_verify_impl(Cipher *self, Py_buffer *data,
                                             Py_buffer *tag)
/*[clinic end generated code: output=036d38a0fdedba9e input=b5ee45e13ec505d3]*/
{
    PyObject *buf;

    buf = _Cipher_crypt(self, data, CIPHER_MODE_DECRYPT);
    if (buf == NULL) {
        return NULL;
    }

    if (_Cipher_verify_tag(self, tag) == NULL) {
        Py_DECREF(buf);
        return NULL;
    }

    return buf;
}

/*[clinic input]
_pystandalone.Cipher.update

    data: Py_buffer

Protect associated data.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_update_impl(Cipher *self, Py_buffer *data)
/*[clinic end generated code: output=8aea00e2c0e763eb input=ce774ce7ddc5e8c9]*/
{
    return _Cipher_update_ad(self, data);
}

/*[clinic input]
_pystandalone.Cipher.digest

Return the digest data as a bytes object.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_digest_impl(Cipher *self)
/*[clinic end generated code: output=ca0c92f67a3aac6d input=d92ff14e2380d3e4]*/
{
    return _Cipher_get_tag(self);
}

/*[clinic input]
_pystandalone.Cipher.verify

    tag: Py_buffer

Verify the given AEAD digest.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_verify_impl(Cipher *self, Py_buffer *tag)
/*[clinic end generated code: output=2c8e2d72c015c078 input=cf4d4fd1a495c7f7]*/
{
    return _Cipher_verify_tag(self, tag);
}

/*[clinic input]
_pystandalone.Cipher.clean

Finalize any remaining buffers.
[clinic start generated code]*/

static PyObject *
_pystandalone_Cipher_clean_impl(Cipher *self)
/*[clinic end generated code: output=fa8d7c88cbdea4c8 input=e334120cdcc73ca7]*/
{
    _Cipher_clean(self);
    Py_RETURN_NONE;
}

static PyMethodDef Cipher_methods[] = {
    _PYSTANDALONE_CIPHER_ENCRYPT_METHODDEF
    _PYSTANDALONE_CIPHER_ENCRYPT_AND_DIGEST_METHODDEF
    _PYSTANDALONE_CIPHER_DECRYPT_METHODDEF
    _PYSTANDALONE_CIPHER_DECRYPT_AND_VERIFY_METHODDEF
    _PYSTANDALONE_CIPHER_UPDATE_METHODDEF
    _PYSTANDALONE_CIPHER_DIGEST_METHODDEF
    _PYSTANDALONE_CIPHER_VERIFY_METHODDEF
    _PYSTANDALONE_CIPHER_CLEAN_METHODDEF
    {NULL}
};

static PyObject *
Cipher_get_initialized(Cipher *self, void *closure)
{
    PyObject * res = self->state == CIPHER_STATE_INIT ? Py_True : Py_False;
    return Py_INCREF(res), res;
}

static PyObject *
Cipher_get_finalized(Cipher *self, void *closure)
{
    PyObject * res = self->state == CIPHER_STATE_FINAL ? Py_True : Py_False;
    return Py_INCREF(res), res;
}

static PyObject *
Cipher_get_cleaned(Cipher *self, void *closure)
{
    PyObject * res = self->state == CIPHER_STATE_CLEAR ? Py_True : Py_False;
    return Py_INCREF(res), res;
}

static PyObject *
Cipher_get_block_size(Cipher *self, void *closure)
{
    return PyLong_FromLong(EVP_CIPHER_CTX_block_size(self->ctx));
}

static PyObject *
Cipher_get_name(Cipher *self, void *closure)
{
    return py_cipher_name(EVP_CIPHER_CTX_cipher(self->ctx));
}

static PyGetSetDef Cipher_getset[] = {
    {"initialized",
     (getter)Cipher_get_initialized, NULL,
     NULL,
     PyDoc_STR("cipher state.")},
    {"finalized",
     (getter)Cipher_get_finalized, NULL,
     NULL,
     PyDoc_STR("cipher state.")},
    {"cleaned",
     (getter)Cipher_get_cleaned, NULL,
     NULL,
     PyDoc_STR("cipher state.")},
    {"block_size",
     (getter)Cipher_get_block_size, NULL,
     NULL,
     PyDoc_STR("algorithm block size.")},
    {"name",
     (getter)Cipher_get_name, NULL,
     NULL,
     PyDoc_STR("algorithm name.")},
    {NULL}
};

static PyObject *
Cipher_repr(Cipher *self)
{
    PyObject *name_obj, *repr;
    name_obj = py_cipher_name(EVP_CIPHER_CTX_cipher(self->ctx));
    if (name_obj == NULL) {
        return NULL;
    }

    repr = PyUnicode_FromFormat("<Cipher object @ %p (%U)>", self, name_obj);
    Py_DECREF(name_obj);
    return repr;
}

static void
Cipher_dealloc(Cipher *self)
{
    EVP_CIPHER_CTX_cleanup(self->ctx);
    EVP_CIPHER_CTX_free(self->ctx);
    OPENSSL_cleanse(self->key, sizeof(self->key));
    OPENSSL_cleanse(self->iv, sizeof(self->iv));
    PyObject_Del(self);
}

static int
Cipher_traverse(Cipher *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    return 0;
}

static PyType_Slot Cipher_type_slots[] = {
    {Py_tp_dealloc, Cipher_dealloc},
    {Py_tp_methods, Cipher_methods},
    {Py_tp_getset, Cipher_getset},
    {Py_tp_new, PyType_GenericNew},
    {Py_tp_repr, Cipher_repr},
    {Py_tp_traverse, Cipher_traverse},
    {0, 0}
};

static PyType_Spec Cipher_type_spec = {
    .name = "_pystandalone.Cipher",
    .basicsize = sizeof(Cipher),
    // Calling PyType_GetModuleState() on a subclass is not safe.
    // Cipher_type_spec does not have Py_TPFLAGS_BASETYPE flag
    // which prevents to create a subclass.
    // So calling PyType_GetModuleState() in this file is always safe.
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_IMMUTABLETYPE | Py_TPFLAGS_DISALLOW_INSTANTIATION),
    .slots = Cipher_type_slots,
};

/*[clinic input]
_pystandalone.cipher

    name: str
    key: Py_buffer
    iv: Py_buffer = None

Return a new cipher object using the named algorithm.
[clinic start generated code]*/

static PyObject *
_pystandalone_cipher_impl(PyObject *module, const char *name, Py_buffer *key,
                          Py_buffer *iv)
/*[clinic end generated code: output=783b91526b4b69b3 input=f7774c2aceb6efef]*/
{
    const EVP_CIPHER *cipher;

    cipher = EVP_get_cipherbyname(name);
    return (PyObject *)_Cipher_new(module, cipher, key, iv);
}

/*[clinic input]
_pystandalone.chacha20

    key: Py_buffer
    iv: Py_buffer

Return a new chacha20 cipher object.
[clinic start generated code]*/

static PyObject *
_pystandalone_chacha20_impl(PyObject *module, Py_buffer *key, Py_buffer *iv)
/*[clinic end generated code: output=073d8f497e9f9979 input=74cffd0ac8844f92]*/
{
    const EVP_CIPHER *cipher;

    cipher = EVP_get_cipherbynid(NID_chacha20);
    return (PyObject *)_Cipher_new(module, cipher, key, iv);
}

/*[clinic input]
_pystandalone.aes_256_gcm

    key: Py_buffer
    iv: Py_buffer

Return a new AES-256-GCM cipher object.
[clinic start generated code]*/

static PyObject *
_pystandalone_aes_256_gcm_impl(PyObject *module, Py_buffer *key,
                               Py_buffer *iv)
/*[clinic end generated code: output=bd61a2ad8f4b0b90 input=539db828570e4054]*/
{
    const EVP_CIPHER *cipher;

    cipher = EVP_get_cipherbynid(NID_aes_256_gcm);
    return (PyObject *)_Cipher_new(module, cipher, key, iv);
}

/* PublicKey class */

/* Internal methods for PublicKey object */

static PublicKey *
_PublicKey_new(PyObject *module, EVP_PKEY *key)
{
    PyTypeObject *type = get_pystandalone_state(module)->PublicKey_type;
    PublicKey *self;

    self = (PublicKey *)PyObject_New(PublicKey, type);
    if (self == NULL) {
        return NULL;
    }

    self->ctx = EVP_PKEY_CTX_new(key, NULL);
    if (self->ctx == NULL) {
        PyErr_NoMemory();
        Py_DECREF(self);
        return NULL;
    }

    if (!EVP_PKEY_encrypt_init(self->ctx)) {
        _set_exception(PyExc_ValueError);
        Py_DECREF(self);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(self->ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        _set_exception(PyExc_ValueError);
        Py_DECREF(self);
        return NULL;
    }

    return self;
}


/*[clinic input]
_pystandalone.PublicKey.encrypt

    data: Py_buffer

Return the encrypted data as a bytes object.
[clinic start generated code]*/

static PyObject *
_pystandalone_PublicKey_encrypt_impl(PublicKey *self, Py_buffer *data)
/*[clinic end generated code: output=26c660fca2d97da4 input=707cb5434a177083]*/

{
    PyObject *buf;
    size_t out_len;
    unsigned char *out_buf;

    if (!EVP_PKEY_encrypt(self->ctx, NULL, &out_len, data->buf, data->len)) {
        _set_exception(PyExc_ValueError);
        return NULL;
    }

    buf = PyBytes_FromStringAndSize(NULL, out_len);
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    out_buf = (unsigned char *)PyBytes_AS_STRING(buf);
    if (!EVP_PKEY_encrypt(self->ctx, out_buf, &out_len, data->buf, data->len)) {
        _set_exception(PyExc_ValueError);
        Py_DECREF(buf);
        return NULL;
    }

    return buf;
}

/*[clinic input]
_pystandalone.PublicKey.der

Export the public key as DER.
[clinic start generated code]*/

static PyObject *
_pystandalone_PublicKey_der_impl(PublicKey *self)
/*[clinic end generated code: output=e635f0246493bbbc input=fd8c67af030d4b6b]*/
{
    PyObject *buf;
    RSA *rsa;
    int out_len;
    unsigned char *out_buf;

    rsa = EVP_PKEY_get1_RSA(EVP_PKEY_CTX_get0_pkey(self->ctx));
    if (rsa == NULL) {
        _set_exception(PyExc_ValueError);
        return NULL;
    }

    out_len = i2d_RSA_PUBKEY(rsa, NULL);
    if (out_len < 0) {
        _set_exception(PyExc_ValueError);
        return NULL;
    }

    buf = PyBytes_FromStringAndSize(NULL, out_len);
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    out_buf = (unsigned char *)PyBytes_AS_STRING(buf);
    if (i2d_RSA_PUBKEY(rsa, &out_buf) < 0) {
        _set_exception(PyExc_ValueError);
        Py_DECREF(buf);
        return NULL;
    }

    return buf;
}

/*[clinic input]
_pystandalone.PublicKey.pem

Export the public key as PEM.
[clinic start generated code]*/

static PyObject *
_pystandalone_PublicKey_pem_impl(PublicKey *self)
/*[clinic end generated code: output=a0485f2925db5e23 input=cc0d75f5744946d6]*/
{
    PyObject *buf;
    BIO *bio;
    int out_len;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    if (!PEM_write_bio_PUBKEY(bio, EVP_PKEY_CTX_get0_pkey(self->ctx))) {
        _set_exception(PyExc_ValueError);
        BIO_free(bio);
        return NULL;
    }

    out_len = BIO_pending(bio);
    buf = PyBytes_FromStringAndSize(NULL, out_len);
    if (buf == NULL) {
        PyErr_NoMemory();
        BIO_free(bio);
        return NULL;
    }

    if (BIO_read(bio, PyBytes_AS_STRING(buf), out_len) <= 0) {
        _set_exception(PyExc_ValueError);
        BIO_free(bio);
        Py_DECREF(buf);
        return NULL;
    }

    BIO_free(bio);

    return buf;
}

static PyObject *
PublicKey_repr(PublicKey *self)
{
    PyObject *name_obj, *repr;
    name_obj = py_nid_to_name(EVP_PKEY_base_id(EVP_PKEY_CTX_get0_pkey(self->ctx)));
    if (name_obj == NULL) {
        return NULL;
    }

    repr = PyUnicode_FromFormat("<PublicKey object @ %p (%U)>", self, name_obj);
    Py_DECREF(name_obj);
    return repr;
}

static void
PublicKey_dealloc(PublicKey *self)
{
    EVP_PKEY_CTX_free(self->ctx);
    PyObject_Del(self);
}

static int
PublicKey_traverse(PublicKey *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    return 0;
}

static PyMethodDef PublicKey_methods[] = {
    _PYSTANDALONE_PUBLICKEY_ENCRYPT_METHODDEF
    _PYSTANDALONE_PUBLICKEY_DER_METHODDEF
    _PYSTANDALONE_PUBLICKEY_PEM_METHODDEF
    {NULL, NULL}
};

static PyType_Slot PublicKey_type_slots[] = {
    {Py_tp_dealloc, PublicKey_dealloc},
    {Py_tp_methods, PublicKey_methods},
    {Py_tp_new, PyType_GenericNew},
    {Py_tp_repr, PublicKey_repr},
    {Py_tp_traverse, PublicKey_traverse},
    {0, 0}
};

static PyType_Spec PublicKey_type_spec = {
    .name = "_pystandalone.PublicKey",
    .basicsize = sizeof(PublicKey),
    // Calling PyType_GetModuleState() on a subclass is not safe.
    // PublicKey_type_spec does not have Py_TPFLAGS_BASETYPE flag
    // which prevents to create a subclass.
    // So calling PyType_GetModuleState() in this file is always safe.
    .flags = (Py_TPFLAGS_DEFAULT | Py_TPFLAGS_IMMUTABLETYPE | Py_TPFLAGS_DISALLOW_INSTANTIATION),
    .slots = PublicKey_type_slots,
};

/*[clinic input]
_pystandalone.rsa

    key: Py_buffer(accept={buffer, str})

Return a PublicKey object using the given public key.
[clinic start generated code]*/

static PyObject *
_pystandalone_rsa_impl(PyObject *module, Py_buffer *key)
/*[clinic end generated code: output=338f16bde17a0f1d input=412a3fc6d35ee56c]*/
{
    EVP_PKEY *pkey;

    pkey = load_rsa_public_key(key);
    if (pkey == NULL) {
        return NULL;
    }

    return (PyObject *)_PublicKey_new(module, pkey);
}

/*[clinic input]
_pystandalone.rand_bytes

    num: int

Return a given number of random bytes.
[clinic start generated code]*/

static PyObject *
_pystandalone_rand_bytes_impl(PyObject *module, int num)
/*[clinic end generated code: output=50e743d95368db31 input=a731c0536eb2b889]*/
{
    PyObject *buf;
    unsigned char *out_buf;

    buf = PyBytes_FromStringAndSize(NULL, num);
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    out_buf = (unsigned char *)PyBytes_AS_STRING(buf);
    if (!RAND_bytes(out_buf, num)) {
        _set_exception(PyExc_ValueError);
        Py_DECREF(buf);
        return NULL;
    }

    return buf;
}

/*[clinic input]
_pystandalone.get_library

Return a memoryview of the library zip.
[clinic start generated code]*/

static PyObject *
_pystandalone_get_library_impl(PyObject *module)
/*[clinic end generated code: output=bfb7e576b98a2cdd input=70e5f1ef66b86b08]*/
{
    PyObject *res = PyStandalone_GetZip(PYSTANDALONE_LIBRARY_ZIP);
    if (res == NULL) {
        Py_RETURN_NONE;
    }

    return res;
}

/*[clinic input]
_pystandalone.get_bootstrap

Return a memoryview of the bootstrap zip.
[clinic start generated code]*/

static PyObject *
_pystandalone_get_bootstrap_impl(PyObject *module)
/*[clinic end generated code: output=22eba0a6d2829428 input=f6a6973c45bebe5f]*/
{
    PyObject *res = PyStandalone_GetZip(PYSTANDALONE_BOOTSTRAP_ZIP);
    if (res == NULL) {
        Py_RETURN_NONE;
    }

    return res;
}

/*[clinic input]
_pystandalone.get_payload

Return a memoryview of the payload zip.
[clinic start generated code]*/

static PyObject *
_pystandalone_get_payload_impl(PyObject *module)
/*[clinic end generated code: output=3934affc5389cb79 input=d611b93a05556a95]*/
{
    PyObject *res = PyStandalone_GetZip(PYSTANDALONE_PAYLOAD_ZIP);
    if (res == NULL) {
        Py_RETURN_NONE;
    }

    return res;
}

/*[clinic input]
_pystandalone.has_library

Return whether there's a library zip.
[clinic start generated code]*/

static PyObject *
_pystandalone_has_library_impl(PyObject *module)
/*[clinic end generated code: output=04238eaa01e29446 input=3272862d1d74a71a]*/
{
    PyObject *res = PyStandalone_HasLibrary() ? Py_True : Py_False;
    return Py_INCREF(res), res;
}

/*[clinic input]
_pystandalone.has_bootstrap

Return whether there's a bootstrap zip.
[clinic start generated code]*/

static PyObject *
_pystandalone_has_bootstrap_impl(PyObject *module)
/*[clinic end generated code: output=a5e616490f5e50c9 input=24807adbd6092d18]*/
{
    PyObject *res = PyStandalone_HasBootstrap() ? Py_True : Py_False;
    return Py_INCREF(res), res;
}

/*[clinic input]
_pystandalone.has_payload

Return whether there's a payload zip.
[clinic start generated code]*/

static PyObject *
_pystandalone_has_payload_impl(PyObject *module)
/*[clinic end generated code: output=3f6b9eeea5cb6ba3 input=338fbe7842bbb2dd]*/
{
    PyObject *res = PyStandalone_HasPayload() ? Py_True : Py_False;
    return Py_INCREF(res), res;
}

/* List of functions exported by this module */

static PyMethodDef _pystandalone_methods[] = {
    /* Cipher functions */
    _PYSTANDALONE_CIPHER_METHODDEF
    _PYSTANDALONE_CHACHA20_METHODDEF
    _PYSTANDALONE_AES_256_GCM_METHODDEF
    /* PKey functions */
    _PYSTANDALONE_RSA_METHODDEF
    /* Util functions */
    _PYSTANDALONE_RAND_BYTES_METHODDEF
    /* ZIP functions */
    _PYSTANDALONE_GET_LIBRARY_METHODDEF
    _PYSTANDALONE_GET_BOOTSTRAP_METHODDEF
    _PYSTANDALONE_GET_PAYLOAD_METHODDEF
    _PYSTANDALONE_HAS_LIBRARY_METHODDEF
    _PYSTANDALONE_HAS_BOOTSTRAP_METHODDEF
    _PYSTANDALONE_HAS_PAYLOAD_METHODDEF
    {NULL, NULL}
};

/* Module initialization. */

static int
_pystandalone_init_types(PyObject *module)
{
    _pystandalone_state *state = get_pystandalone_state(module);

    state->Cipher_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &Cipher_type_spec, NULL);
    if (state->Cipher_type == NULL) {
        return -1;
    }

    if (PyModule_AddType(module, state->Cipher_type) < 0) {
        return -1;
    }

    state->PublicKey_type = (PyTypeObject *)PyType_FromModuleAndSpec(module, &PublicKey_type_spec, NULL);
    if (state->PublicKey_type == NULL) {
        return -1;
    }

    if (PyModule_AddType(module, state->PublicKey_type) < 0) {
        return -1;
    }

    return 0;
}

/* State for our callback function so that it can accumulate a result. */
typedef struct _internal_name_mapper_state {
    PyObject *set;
    int error;
} _InternalNameMapperState;

/* A callback function to pass to OpenSSL's OBJ_NAME_do_all(...) */
static void
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
_openssl_cipher_name_mapper(EVP_CIPHER *cipher, void *arg)
#else
_openssl_cipher_name_mapper(const EVP_CIPHER *cipher, const char *from,
                            const char *to, void *arg)
#endif
{
    _InternalNameMapperState *state = (_InternalNameMapperState *)arg;
    PyObject *py_name;

    assert(state != NULL);
    if (cipher == NULL) {
        return;
    }

    py_name = py_cipher_name(cipher);
    if (py_name == NULL) {
        state->error = 1;
    }
    else {
        if (PySet_Add(state->set, py_name) != 0) {
            state->error = 1;
        }
        Py_DECREF(py_name);
    }
}

/* Ask OpenSSL for a list of supported ciphers, filling in a Python set. */
static int
_pystandalone_init_cipher_names(PyObject *module)
{
    _InternalNameMapperState state = {
        .set = PyFrozenSet_New(NULL),
        .error = 0
    };
    if (state.set == NULL) {
        return -1;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // get algorithms from all activated providers in default context
    EVP_CIPHER_do_all_provided(NULL, &_openssl_cipher_name_mapper, &state);
#else
    EVP_CIPHER_do_all(&_openssl_cipher_name_mapper, &state);
#endif

    if (state.error) {
        Py_DECREF(state.set);
        return -1;
    }

    if (PyModule_AddObject(module, "ciphers", state.set) < 0) {
        Py_DECREF(state.set);
        return -1;
    }

    return 0;
}

static int
_pystandalone_traverse(PyObject *module, visitproc visit, void *arg)
{
    _pystandalone_state *state = get_pystandalone_state(module);
    Py_VISIT(state->Cipher_type);
    Py_VISIT(state->PublicKey_type);
    return 0;
}

static int
_pystandalone_clear(PyObject *module)
{
    _pystandalone_state *state = get_pystandalone_state(module);
    Py_CLEAR(state->Cipher_type);
    Py_CLEAR(state->PublicKey_type);
    return 0;
}

static void
_pystandalone_free(void *module)
{
    _pystandalone_clear((PyObject *)module);
}

static struct PyModuleDef_Slot _pystandalone_slots[] = {
    {Py_mod_exec, _pystandalone_init_types},
    {Py_mod_exec, _pystandalone_init_cipher_names},
    {0, NULL}
};

static struct PyModuleDef _pystandalone = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_pystandalone",
    .m_size = sizeof(_pystandalone_state),
    .m_methods = _pystandalone_methods,
    .m_slots = _pystandalone_slots,
    .m_traverse = _pystandalone_traverse,
    .m_clear = _pystandalone_clear,
    .m_free = _pystandalone_free,
};

PyMODINIT_FUNC
PyInit__pystandalone(void)
{
    return PyModuleDef_Init(&_pystandalone);
}
