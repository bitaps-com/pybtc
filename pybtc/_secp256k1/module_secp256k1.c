#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#define USE_NUM_GMP
#include "secp256k1.h"
#include "secp256k1_recovery.h"




secp256k1_context *secp256k1_precomp_context_sign;
secp256k1_context *secp256k1_precomp_context_verify;
static int context_exist = 0;



static PyObject *secp256k1_secp256k1_ec_pubkey_tweak_add(PyObject *self, PyObject *args) {
    Py_buffer pubkey;
    Py_buffer tweak;
    int flag;
    if (!PyArg_ParseTuple(args,"y*y*i", &pubkey, &tweak, &flag)) { return NULL; }
    secp256k1_pubkey data;
    int t = secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &data, pubkey.buf, pubkey.len);
    PyBuffer_Release(&pubkey);
    if (t==0) { return Py_BuildValue("b", -1); }

    t = secp256k1_ec_pubkey_tweak_add(secp256k1_precomp_context_verify, &data, tweak.buf);
    PyBuffer_Release(&tweak);
    if (t==0) { return Py_BuildValue("b", -2); }

    size_t outl = 33;
    if (flag == 1) {
      outl = 33;
      flag = SECP256K1_EC_COMPRESSED;
    } else {
      outl = 65;
      flag = SECP256K1_EC_UNCOMPRESSED;
    }
    unsigned char pubkeyo[outl];
    t = secp256k1_ec_pubkey_serialize(secp256k1_context_no_precomp, pubkeyo, &outl, &data, flag);
    if (t != 1) { return Py_BuildValue("b", 0); }
    PyObject *return_value = Py_BuildValue("y#", pubkeyo, outl);
    Py_DECREF(pubkeyo);
    return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_add_points(PyObject *self, PyObject *args) {
    Py_buffer a;
    Py_buffer b;
    int flag;
    if (!PyArg_ParseTuple(args,"y*y*i", &a, &b, &flag)) { return NULL; }
    secp256k1_pubkey data[2];
    int t = secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, data, a.buf, a.len);
    PyBuffer_Release(&a);
    if (t==0) { return Py_BuildValue("b", -1); }

    t = secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, data + 1, b.buf, b.len);
    PyBuffer_Release(&b);
    if (t==0) { return Py_BuildValue("b", -1); }
    secp256k1_pubkey out;
    const secp256k1_pubkey* d[2];
    d[0] = &data[0];
    d[1] = &data[1];

    t = secp256k1_ec_pubkey_combine(secp256k1_precomp_context_sign, &out,
                                    d, 2);

    size_t outl;
    if (flag == 1) {
      outl = 33;
      flag = SECP256K1_EC_COMPRESSED;
    } else {
      outl = 65;
      flag = SECP256K1_EC_UNCOMPRESSED;
    }
    unsigned char pubkeyo[outl];
    t = secp256k1_ec_pubkey_serialize(secp256k1_context_no_precomp, pubkeyo, &outl, &out, flag);
    if (t != 1) { return Py_BuildValue("b", 0); }
    PyObject *return_value = Py_BuildValue("y#", pubkeyo, outl);
    Py_DECREF(pubkeyo);
    return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_signature_serialize_compact(PyObject *self, PyObject *args) {
    Py_buffer sig;
    if (!PyArg_ParseTuple(args,"y*", &sig)) { return NULL; }
    unsigned char compact_sig[64] ;
    size_t outputLen = 64;
    int t = secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_no_precomp,
                                                        compact_sig, sig.buf);
    PyBuffer_Release(&sig);

    if (t==0) { return Py_BuildValue("b", 0); }
    PyObject *return_value = Py_BuildValue("y#", &compact_sig, outputLen);
    Py_DECREF(compact_sig);
    return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_recoverable_signature_serialize_compact(PyObject *self, PyObject *args) {
    Py_buffer sig;
    if (!PyArg_ParseTuple(args,"y*", &sig)) { return NULL; }
    unsigned char compact_sig[65];
    int rec_id = 0;
    size_t outputLen = 65;
    int t = secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_no_precomp,
                                                        compact_sig + 1, &rec_id, sig.buf);
    PyBuffer_Release(&sig);
    compact_sig[0] = rec_id;

    if (t==0) { return Py_BuildValue("b", 0); }
    PyObject *return_value = Py_BuildValue("y#", &compact_sig, outputLen);
    Py_DECREF(compact_sig);
    return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_signature_serialize_der(PyObject *self, PyObject *args) {
    Py_buffer sig;
    if (!PyArg_ParseTuple(args,"y*", &sig)) { return NULL; }
    secp256k1_ecdsa_signature signature;
    int t = secp256k1_ecdsa_signature_parse_compact(secp256k1_context_no_precomp,
                                                              &signature,
                                                              sig.buf);
    PyBuffer_Release(&sig);
    if (t==0) { return Py_BuildValue("b", 0); }
    unsigned char outputSer[72];
    size_t outputLen = 72;
    t = secp256k1_ecdsa_signature_serialize_der(secp256k1_context_no_precomp,
                                            outputSer,
                                            &outputLen,
                                            &signature);
    if (t==0) { return Py_BuildValue("b", 0); }
    PyObject *return_value = Py_BuildValue("y#", &outputSer, outputLen);
    Py_DECREF(outputSer);
    return return_value;
}

static PyObject *secp256k1_secp256k1_nonce_rfc6979(PyObject *self, PyObject *args) {
  unsigned char nonce[32];
  Py_buffer msg32;
  Py_buffer key32;
  unsigned int counter;
  if (!PyArg_ParseTuple(args,"y*y*b", &msg32, &key32, &counter)) {  return NULL; }

  int r = secp256k1_nonce_function_rfc6979(nonce, msg32.buf, key32.buf, NULL, NULL, counter);
  PyBuffer_Release(&msg32);
  PyBuffer_Release(&key32);
  if (r == 0 ) { return Py_BuildValue("b", 0); }
  PyObject *return_value = Py_BuildValue("y#", &nonce, 32);
  Py_DECREF(nonce);
  return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_recover(PyObject *self, PyObject *args) {
    Py_buffer message;
    Py_buffer sig;
    int rec_id;
    int compressed;
    int der;
    int r;


    secp256k1_ecdsa_recoverable_signature signature_recoverable;

    if (!PyArg_ParseTuple(args,"y*y*iii", &sig, &message, &rec_id, &compressed, &der)) { return NULL; }
    if (der) {
        secp256k1_ecdsa_signature signature;
        r = secp256k1_ecdsa_signature_parse_der(secp256k1_context_no_precomp,
                                                &signature,
                                                sig.buf, sig.len);
        PyBuffer_Release(&sig);

        unsigned char compact_sig[64] ;

        if (r != 1) { return Py_BuildValue("b", -1);}

        r = secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_no_precomp,
                                                        compact_sig, &signature);
        if (r != 1) { return Py_BuildValue("b", -1);}

        r = secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_no_precomp,
                                                                &signature_recoverable,
                                                                compact_sig,
                                                                rec_id);
        if (r != 1) { return Py_BuildValue("b", -2);}

    } else {
        r = secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_no_precomp,
                                                                &signature_recoverable,
                                                                sig.buf, rec_id);
        if (r != 1) { return Py_BuildValue("b", -2);}

    }

    secp256k1_pubkey pubkey;
    r = secp256k1_ecdsa_recover(secp256k1_precomp_context_verify,
                                &pubkey,
                                &signature_recoverable, message.buf);
    PyBuffer_Release(&message);
    if (r != 1) { return Py_BuildValue("b", 0);}

    size_t outl;
    if (compressed == 1) {
      outl = 33;
      compressed = SECP256K1_EC_COMPRESSED;
    } else {
      outl = 65;
      compressed = SECP256K1_EC_UNCOMPRESSED;
    }
    unsigned char pubkeyo[outl];
    r = secp256k1_ec_pubkey_serialize(secp256k1_context_no_precomp, pubkeyo, &outl, &pubkey, compressed);
    if (r != 1) {
      return Py_BuildValue("b", -3);
    }
    PyObject *return_value = Py_BuildValue("y#", pubkeyo, outl);
    Py_DECREF(pubkeyo);
    return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_verify(PyObject *self, PyObject *args) {
    Py_buffer message;
    Py_buffer pub;
    Py_buffer sig;
    if (!PyArg_ParseTuple(args,"y*y*y*", &sig, &pub, &message)) { return NULL; }

    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    int r = secp256k1_ecdsa_signature_parse_der(secp256k1_context_no_precomp,
                                                &signature,
                                                sig.buf, sig.len);
    PyBuffer_Release(&sig);
    if (r != 1) { return Py_BuildValue("b", -1);}

    r = secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp,
                                  &pubkey,
                                  pub.buf, pub.len);
    PyBuffer_Release(&pub);

    if (r != 1) { return Py_BuildValue("b", -2);}

    r = secp256k1_ecdsa_verify(secp256k1_precomp_context_verify,
                               &signature,
                               message.buf,
                               &pubkey);
    PyBuffer_Release(&message);
    if (r != 1) { return Py_BuildValue("b", 0);}
    return Py_BuildValue("b", 1);
}

static PyObject *secp256k1_secp256k1_context_create(PyObject *self, PyObject *args) {
  if (context_exist == 0 ) {
      secp256k1_context *s = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
      secp256k1_context *v = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
      secp256k1_precomp_context_sign = s;
      secp256k1_precomp_context_verify = v;
      context_exist = 1;
      return Py_BuildValue("b", 1);
  }
  return Py_BuildValue("b", 0);
}

static PyObject *secp256k1_secp256k1_context_randomize(PyObject *self, PyObject *args) {
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args,"y*", &buffer)) {  return NULL; }
    int r = 0;
    r += secp256k1_context_randomize(secp256k1_precomp_context_sign, buffer.buf);
    r += secp256k1_context_randomize(secp256k1_precomp_context_sign, buffer.buf);
    PyBuffer_Release(&buffer);
    if (r == 2) { return Py_BuildValue("b", 1); }
    else { return Py_BuildValue("b", 0); }

}

static PyObject *secp256k1_secp256k1_ec_pubkey_create(PyObject *self, PyObject *args) {

    int flag;
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args,"y*i", &buffer, &flag)) { return NULL; }
    secp256k1_pubkey pubkey;

    int r = 0;
    r = secp256k1_ec_pubkey_create(secp256k1_precomp_context_sign, &pubkey, buffer.buf);
    PyBuffer_Release(&buffer);
    if (r != 1) {
      return Py_BuildValue("b", (Py_ssize_t)0);
    }

    size_t outl;
    if (flag == 1) {
      outl = 33;
      flag = SECP256K1_EC_COMPRESSED;
    } else {
      outl = 65;
      flag = SECP256K1_EC_UNCOMPRESSED;
    }
    unsigned char pubkeyo[outl];


    r = secp256k1_ec_pubkey_serialize(secp256k1_precomp_context_verify, pubkeyo, &outl, &pubkey, flag);
    if (r != 1) {
      return Py_BuildValue("b", (Py_ssize_t)0);
    }
    PyObject *return_value =  Py_BuildValue("y#", pubkeyo, outl);

    Py_DECREF(pubkeyo);
    return return_value;
}

static PyObject *secp256k1_secp256k1_ecdsa_sign(PyObject *self, PyObject *args) {
    Py_buffer msg;
    Py_buffer private_key;
    int der_encoding;
    if (!PyArg_ParseTuple(args,"y*y*i", &msg, &private_key, &der_encoding)) {
      return NULL;
    }
    secp256k1_ecdsa_recoverable_signature signature;
    int r=1;
    r = secp256k1_ecdsa_sign_recoverable(secp256k1_precomp_context_sign,
                                         &signature,
                                         msg.buf,
                                         private_key.buf,
                                         NULL, NULL);
    PyBuffer_Release(&private_key);
    PyBuffer_Release(&msg);
    if (r != 1) {
      return Py_BuildValue("b", 0);
    }
    if (der_encoding == 0) {
        unsigned char outputSer[65];
        size_t outputLen = 65;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_no_precomp,
                                                                outputSer + 1,
                                                                 (int *) outputSer,
                                                                 &signature);
        PyObject *return_value = Py_BuildValue("y#", &outputSer, outputLen);
        Py_DECREF(outputSer);
        return return_value;
    } else {
        unsigned char outputSer[72];
        size_t outputLen = 72;
        secp256k1_ecdsa_signature_serialize_der(secp256k1_context_no_precomp,
                                                outputSer,
                                                &outputLen,
                                                (const secp256k1_ecdsa_signature *)&signature);
        PyObject *return_value = Py_BuildValue("y#", &outputSer, outputLen);
        Py_DECREF(outputSer);
        return return_value;
    }
}


static PyMethodDef module_methods[] = {
    {"secp256k1_context_randomize", secp256k1_secp256k1_context_randomize, METH_VARARGS, "Randomize context"},
    {"secp256k1_context_create", secp256k1_secp256k1_context_create, METH_VARARGS, "Returns context"},
    {"secp256k1_ec_pubkey_create", secp256k1_secp256k1_ec_pubkey_create, METH_VARARGS, "Returns public key"},
    {"secp256k1_ecdsa_sign", secp256k1_secp256k1_ecdsa_sign, METH_VARARGS, "Sign message"},
    {"secp256k1_ecdsa_verify", secp256k1_secp256k1_ecdsa_verify, METH_VARARGS, "Verify signature"},
    {"secp256k1_ecdsa_recover", secp256k1_secp256k1_ecdsa_recover, METH_VARARGS, "Recover public key from signature"},
    {"secp256k1_nonce_rfc6979", secp256k1_secp256k1_nonce_rfc6979, METH_VARARGS, "Create rfc6979 nonce"},
    {"secp256k1_ecdsa_signature_serialize_der", secp256k1_secp256k1_ecdsa_signature_serialize_der, METH_VARARGS, "Serialize to DER"},
    {"secp256k1_ecdsa_signature_serialize_compact", secp256k1_secp256k1_ecdsa_signature_serialize_compact, METH_VARARGS, "Serialize to compact"},
    {"secp256k1_ecdsa_recoverable_signature_serialize_compact", secp256k1_secp256k1_ecdsa_recoverable_signature_serialize_compact, METH_VARARGS, "Serialize to compact"},
    {"secp256k1_ecdsa_add_points", secp256k1_secp256k1_ecdsa_add_points, METH_VARARGS, "2 points addition"},
    {"secp256k1_ec_pubkey_tweak_add", secp256k1_secp256k1_ec_pubkey_tweak_add, METH_VARARGS, "tweak addition "},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef _module_secp256k1 = {
    PyModuleDef_HEAD_INIT,
    "_secp256k1",
    "...",
    -1,
    module_methods
};



PyMODINIT_FUNC PyInit__secp256k1(void) {
    PyObject *m;
    m = PyModule_Create(&_module_secp256k1);
    PyModule_AddObject(m, "SECP256K1_CONTEXT_NO_PRECOMP", PyCapsule_New(&secp256k1_context_no_precomp,
                                                                        "secp256k1_context", NULL));
    PyModule_AddIntMacro(m, SECP256K1_CONTEXT_VERIFY);
    PyModule_AddIntMacro(m, SECP256K1_CONTEXT_SIGN);
    PyModule_AddIntMacro(m, SECP256K1_CONTEXT_NONE);
    PyModule_AddIntMacro(m, SECP256K1_EC_COMPRESSED);
    PyModule_AddIntMacro(m, SECP256K1_EC_UNCOMPRESSED);
    PyModule_AddIntMacro(m, SECP256K1_TAG_PUBKEY_EVEN);
    PyModule_AddIntMacro(m, SECP256K1_TAG_PUBKEY_ODD);
    PyModule_AddIntMacro(m, SECP256K1_TAG_PUBKEY_UNCOMPRESSED);
    PyModule_AddIntMacro(m, SECP256K1_TAG_PUBKEY_HYBRID_EVEN);
    PyModule_AddIntMacro(m, SECP256K1_TAG_PUBKEY_HYBRID_ODD);

    return m;
}

