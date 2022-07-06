#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "common.h"
#include "sha256.h"
#include "base58.h"
#include "hash.h"
#include <vector>
#include <iostream>

// Map a value x that is uniformly distributed in the range [0, 2^64) to a
// value uniformly distributed in [0, n) by returning the upper 64 bits of
// x * n.
//
// See: https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
static uint64_t MapIntoRange(uint64_t x, uint64_t n)
{
#ifdef __SIZEOF_INT128__
    return (static_cast<unsigned __int128>(x) * static_cast<unsigned __int128>(n)) >> 64;
#else
    // To perform the calculation on 64-bit numbers without losing the
    // result to overflow, split the numbers into the most significant and
    // least significant 32 bits and perform multiplication piece-wise.
    //
    // See: https://stackoverflow.com/a/26855440
    uint64_t x_hi = x >> 32;
    uint64_t x_lo = x & 0xFFFFFFFF;
    uint64_t n_hi = n >> 32;
    uint64_t n_lo = n & 0xFFFFFFFF;

    uint64_t ac = x_hi * n_hi;
    uint64_t ad = x_hi * n_lo;
    uint64_t bc = x_lo * n_hi;
    uint64_t bd = x_lo * n_lo;

    uint64_t mid34 = (bd >> 32) + (bc & 0xFFFFFFFF) + (ad & 0xFFFFFFFF);
    uint64_t upper64 = ac + (bc >> 32) + (ad >> 32) + (mid34 >> 32);
    return upper64;
#endif
}


static PyObject* crypto_map_into_range(PyObject *, PyObject* args) {
    uint64_t x, n;
    if (!PyArg_ParseTuple(args,"KK", &x, &n)) return NULL;

    uint64_t r = MapIntoRange(x, n);

    PyObject *return_value = Py_BuildValue("K", r);

    return return_value;
}

static PyObject* crypto_siphash(PyObject *, PyObject* args) {
    Py_buffer buffer;
    uint64_t k0, k1;
    if (!PyArg_ParseTuple(args,"KKy*", &k0, &k1, &buffer)) return NULL;

    uint64_t hash = CSipHasher(k0, k1).Write((const unsigned char*) buffer.buf, buffer.len).Finalize();

    PyBuffer_Release(&buffer);
    PyObject *return_value = Py_BuildValue("K", hash);

    return return_value;
}


static PyObject* crypto_murmurhash3(PyObject *, PyObject* args) {
    unsigned int nHashSeed;
    Py_buffer buffer;

    std::vector<unsigned char> vDataToHash;
    if (!PyArg_ParseTuple(args,"Iy*", &nHashSeed, &buffer )) return NULL;
    unsigned char *charBuf = (unsigned char*)buffer.buf;
    std::vector<unsigned char> v(charBuf, charBuf + buffer.len);
    unsigned int r = MurmurHash3(nHashSeed, v);
    PyBuffer_Release(&buffer);
    PyObject *return_value = Py_BuildValue("I", r);

    return return_value;
}


static PyObject* crypto_decode_base58(PyObject *, PyObject* args) {
    char *s;
    if (!PyArg_ParseTuple(args,"s", &s)) return NULL;

    std::vector<unsigned char> result;
    if (!DecodeBase58(s, result)) {
      PyErr_SetString(PyExc_ValueError, "Base58 decode error");
      return NULL;
    }
    unsigned char r[result.size()];
    unsigned char *rp = r;
    for (auto i = result.begin(); i != result.end(); ++i) {
      *rp = *i;
      rp++;
    }
    PyObject *return_value = Py_BuildValue("y#", r, result.size());
    Py_DECREF(r);
    return return_value;
}

static PyObject* crypto_encode_base58(PyObject *, PyObject* args) {
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args,"y*", &buffer)) return NULL;
    std::string result = EncodeBase58((const unsigned char*)buffer.buf,
                                      (const unsigned char*)buffer.buf + buffer.len);
    PyBuffer_Release(&buffer);
    const char * c = result.c_str();
    PyObject *return_value = Py_BuildValue("s", c);
    Py_DECREF(c);
    return return_value;
}

static PyObject* crypto_double_sha256(PyObject *, PyObject* args) {
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args,"y*", &buffer)) return NULL;
    unsigned char h[CSHA256::OUTPUT_SIZE];
    CSHA256().Write((const unsigned char*)buffer.buf, buffer.len).Finalize(h);
    PyBuffer_Release(&buffer);
    uint8_t h2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(h, CSHA256::OUTPUT_SIZE).Finalize(h2);
    PyObject *return_value = Py_BuildValue("y#", h2, CSHA256::OUTPUT_SIZE);
    Py_DECREF(h2);
    return return_value;
}

static PyObject* crypto_sha256(PyObject *, PyObject* args) {
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args,"y*", &buffer)) return NULL;
    unsigned char h[CSHA256::OUTPUT_SIZE];
    CSHA256().Write((const unsigned char*)buffer.buf, buffer.len).Finalize(h);
    PyBuffer_Release(&buffer);
    PyObject *return_value = Py_BuildValue("y#", h, CSHA256::OUTPUT_SIZE);
    Py_DECREF(h);
    return return_value;
}



static PyMethodDef module_methods[] = {
    { "__map_into_range__", (PyCFunction)crypto_map_into_range, METH_VARARGS, nullptr },
    { "__siphash__", (PyCFunction)crypto_siphash, METH_VARARGS, nullptr },
    { "__murmurhash3__", (PyCFunction)crypto_murmurhash3, METH_VARARGS, nullptr },
    { "__decode_base58__", (PyCFunction)crypto_decode_base58, METH_VARARGS, nullptr },
    { "__encode_base58__", (PyCFunction)crypto_encode_base58, METH_VARARGS, nullptr },
    { "__double_sha256__", (PyCFunction)crypto_double_sha256, METH_VARARGS, nullptr },
    { "__sha256__", (PyCFunction)crypto_sha256, METH_VARARGS, nullptr },
    { nullptr, nullptr, 0, nullptr }
};

static PyModuleDef _module_crypto = {
    PyModuleDef_HEAD_INIT,
    "_module_crypto",
    "Provides some functions, but faster",
    0,
    module_methods
};





PyMODINIT_FUNC PyInit__crypto(void) {
    PyObject *m;
    m = PyModule_Create(&_module_crypto);
    return m;
}

