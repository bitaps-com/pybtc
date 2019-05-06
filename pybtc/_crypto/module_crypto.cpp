#include <Python.h>
#include "common.h"
#include "sha256.h"
#include "base58.h"
#include <vector>
#include <iostream>


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

