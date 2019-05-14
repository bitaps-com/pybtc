#include <Python.h>



#ifndef Py_TYPE
 #define Py_TYPE(ob) (((PyObject*)(ob))->ob_type)
#endif

#define GET_NODE(d, key) (Node *) Py_TYPE(d)->tp_as_mapping->mp_subscript((d), (key))
#define PUT_NODE(d, key, node) Py_TYPE(d)->tp_as_mapping->mp_ass_subscript((d), (key), ((PyObject *)node))


typedef struct _Node {
    PyObject_HEAD
    PyObject * value;
    PyObject * key;
    struct _Node * prev;
    struct _Node * next;
} Node;

static void node_dealloc(Node* self)
{
    Py_DECREF(self->key);
    Py_DECREF(self->value);
    assert(self->prev == NULL);
    assert(self->next == NULL);
    PyObject_Del((PyObject*)self);
}

static PyObject*node_repr(Node* self) { return PyObject_Repr(self->value);}

static PyTypeObject NodeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ple.Node",              /* tp_name */
    sizeof(Node),            /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)node_dealloc,/* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_compare */
    (reprfunc)node_repr,     /* tp_repr */
    0,                       /* tp_as_number */
    0,                       /* tp_as_sequence */
    0,                       /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,      /* tp_flags */
    "Linked List Node",      /* tp_doc */
    0,                       /* tp_traverse */
    0,                       /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    0,                       /* tp_methods */
    0,                       /* tp_members */
    0,                       /* tp_getset */
    0,                       /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    0,                       /* tp_init */
    0,                       /* tp_alloc */
    0,                       /* tp_new */
};

typedef struct {
    PyObject_HEAD
    PyObject * dict;
    Node * first;
    Node * last;
    Py_ssize_t size;
} PLE;


static void ple_remove_node(PLE *self, Node* node)
{
    if (self->first == node) {
        self->first = node->next;
    }
    if (self->last == node) {
        self->last = node->prev;
    }
    if (node->prev) {
        node->prev->next = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    node->next = node->prev = NULL;
}

static void ple_add_node_at_head(PLE *self, Node* node)
{
    node->prev = NULL;
    if (!self->first) {
        self->first = self->last = node;
        node->next = NULL;
    } else {
        node->next = self->first;
        if (node->next) {
            node->next->prev = node;
        }
        self->first = node;
    }
}

static void ple_add_node_at_tail(PLE *self, Node* node)
{
    node->next = NULL;
    if (!self->first) {
        self->first = self->last = node;
        node->prev = NULL;
    } else {
        node->prev = self->last;
        if (node->prev) {
            node->prev->next = node;
        }
        self->last = node;
    }
}

static void ple_delete_last(PLE *self)
{
    Node* n = self->last;
    if (!self->last)  return;
    ple_remove_node(self, n);
    PyDict_DelItem(self->dict, n->key);
}


static Py_ssize_t ple_length(PLE *self) {return PyDict_Size(self->dict);}

static PyObject *PLE_contains_key(PLE *self, PyObject *key)
{
    if (PyDict_Contains(self->dict, key)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *PLE_contains(PLE *self, PyObject *args)
{
    PyObject *key;
    if (!PyArg_ParseTuple(args, "O", &key)) return NULL;

    return PLE_contains_key(self, key);
}

static int PLE_seq_contains(PLE *self, PyObject *key) {return PyDict_Contains(self->dict, key);}

static PyObject *ple_subscript(PLE *self, register PyObject *key)
{
    Node *node = GET_NODE(self->dict, key);
    if (!node) return NULL;

    Py_INCREF(node->value);
    Py_DECREF(node);
    return node->value;
}

static PyObject *PLE_pop(PLE *self)
{

    if (self->last) {
        PyObject *tuple = PyTuple_New(2);
        Py_INCREF(self->last->key);
        PyTuple_SET_ITEM(tuple, 0, self->last->key);
        Py_INCREF(self->last->value);
        PyTuple_SET_ITEM(tuple, 1, self->last->value);
        Node* n = self->last;
        ple_remove_node(self, n);
        PyDict_DelItem(self->dict, n->key);
        return tuple;
    }
    else Py_RETURN_NONE;
}


static PyObject *PLE_get(PLE *self, PyObject *args)
{
    PyObject *key;
    PyObject *instead = NULL;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "O|O", &key, &instead)) return NULL;

    result = ple_subscript(self, key);
    PyErr_Clear();  /* GET_NODE sets an exception on miss. Shut it up. */
    if (result) return result;

    if (!instead) { Py_RETURN_NONE; }

    Py_INCREF(instead);
    return instead;
}


static PyObject *PLE_delete(PLE *self, PyObject *args)
{

    PyObject *key;
    PyObject *instead = NULL;
    if (!PyArg_ParseTuple(args, "O|O", &key, &instead)) return NULL;
    Node *node = GET_NODE(self->dict, key);

    if (!node) {
       if (!instead) {
       Py_XDECREF(node);
       Py_RETURN_NONE; }

       Py_INCREF(instead);
       Py_XDECREF(node);
       return instead;
    }




    PyObject *tuple = PyTuple_New(2);

    Py_INCREF(node->key);
    PyTuple_SET_ITEM(tuple, 0, node->key);
    Py_INCREF(node->value);
    PyTuple_SET_ITEM(tuple, 1, node->value);
    ple_remove_node(self, node);
    PyDict_DelItem(self->dict, node->key);
    Py_XDECREF(node);
    return tuple;
}




static int ple_append(PLE *self, PyObject *key, PyObject *value)
{
    int res = 0;
    Node *node = GET_NODE(self->dict, key);
    PyErr_Clear();  /* GET_NODE sets an exception on miss. Shut it up. */

    if (value) {
        if (node) {
            Py_INCREF(value);
            Py_DECREF(node->value);
            node->value = value;
            res = 0;
        } else {
            node = PyObject_NEW(Node, &NodeType);
            node->key = key;
            node->value = value;
            node->next = node->prev = NULL;

            Py_INCREF(key);
            Py_INCREF(value);

            res = PUT_NODE(self->dict, key, node);
            if (res == 0) {
                if (self->size > 0 && ple_length(self) > self->size) ple_delete_last(self);
                ple_add_node_at_tail(self, node);
            }
        }
    } else {

        if (PUT_NODE(self->dict, key, NULL) == 0)  ple_remove_node(self, node);
    }

    Py_XDECREF(node);
    return res;
}


static int ple_ass_sub(PLE *self, PyObject *key, PyObject *value)
{
    int res = 0;
    Node *node = GET_NODE(self->dict, key);
    PyErr_Clear();  /* GET_NODE sets an exception on miss. Shut it up. */

    if (value) {
        if (node) {
            Py_INCREF(value);
            Py_DECREF(node->value);
            node->value = value;
            res = 0;
        } else {
            node = PyObject_NEW(Node, &NodeType);
            node->key = key;
            node->value = value;
            node->next = node->prev = NULL;

            Py_INCREF(key);
            Py_INCREF(value);

            res = PUT_NODE(self->dict, key, node);
            if (res == 0) {
                if (self->size > 0 && ple_length(self) > self->size) ple_delete_last(self);
                ple_add_node_at_head(self, node);
            }
        }
    } else {
        if (PUT_NODE(self->dict, key, NULL) == 0)  ple_remove_node(self, node);
    }

    Py_XDECREF(node);
    return res;
}

static int ple_put(PLE *self, PyObject *key, PyObject *value)
{
    int res = 0;

    Node *node = PyObject_NEW(Node, &NodeType);
    node->key = key;
    node->value = value;
    node->next = node->prev = NULL;

    Py_INCREF(key);
    Py_INCREF(value);

    res = PUT_NODE(self->dict, key, node);
    if (res == 0) {
        if (self->size > 0 && ple_length(self) > self->size) ple_delete_last(self);
        ple_add_node_at_head(self, node);
    }

    Py_XDECREF(node);
    return res;
}

static PyMappingMethods PLE_as_mapping = {
    (lenfunc)ple_length,        /*mp_length*/
    (binaryfunc)ple_subscript,  /*mp_subscript*/
    (objobjargproc)ple_ass_sub, /*mp_ass_subscript*/
};

static PyObject *collect(PLE *self, PyObject * (*getterfunc)(Node *))
{
    register PyObject *v;
    Node *curr;
    int i;
    v = PyList_New(ple_length(self));
    if (v == NULL)
        return NULL;
    curr = self->first;
    i = 0;

    while (curr) {
        PyList_SET_ITEM(v, i++, getterfunc(curr));
        curr = curr->next;
    }
    assert(i == ple_length(self));
    return v;
}

static PyObject *get_key(Node *node)
{
    Py_INCREF(node->key);
    return node->key;
}

static PyObject *PLE_append(PLE *self, PyObject *args, PyObject *kwargs)
{
	PyObject *key, *value;
	PyObject *arg = NULL;
	Py_ssize_t pos = 0;

	if ((PyArg_ParseTuple(args, "|O", &arg))) {
		if (arg && PyDict_Check(arg)) {
			while (PyDict_Next(arg, &pos, &key, &value))
				ple_append(self, key, value);
		}
	}

	if (kwargs != NULL && PyDict_Check(kwargs)) {
		while (PyDict_Next(kwargs, &pos, &key, &value))
			ple_append(self, key, value);
	}

	Py_RETURN_NONE;
}

static PyObject *PLE_update(PLE *self, PyObject *args, PyObject *kwargs)
{
	PyObject *key, *value;
	PyObject *arg = NULL;
	Py_ssize_t pos = 0;

	if ((PyArg_ParseTuple(args, "|O", &arg))) {
		if (arg && PyDict_Check(arg)) {
			while (PyDict_Next(arg, &pos, &key, &value))
				ple_ass_sub(self, key, value);
		}
	}

	if (kwargs != NULL && PyDict_Check(kwargs)) {
		while (PyDict_Next(kwargs, &pos, &key, &value))
			ple_ass_sub(self, key, value);
	}

	Py_RETURN_NONE;
}

static PyObject *PLE_put(PLE *self, PyObject *args, PyObject *kwargs)
{
	PyObject *key, *value;
	PyObject *arg = NULL;
	Py_ssize_t pos = 0;

	if ((PyArg_ParseTuple(args, "|O", &arg))) {
		if (arg && PyDict_Check(arg)) {
			while (PyDict_Next(arg, &pos, &key, &value))
				ple_put(self, key, value);
		}
	}

	if (kwargs != NULL && PyDict_Check(kwargs)) {
		while (PyDict_Next(kwargs, &pos, &key, &value))
			ple_put(self, key, value);
	}

	Py_RETURN_NONE;
}

static PyObject *PLE_peek_first_item(PLE *self)
{
    if (self->first) {
        PyObject *tuple = PyTuple_New(2);
        Py_INCREF(self->first->key);
        PyTuple_SET_ITEM(tuple, 0, self->first->key);
        Py_INCREF(self->first->value);
        PyTuple_SET_ITEM(tuple, 1, self->first->value);
        return tuple;
    }
    else Py_RETURN_NONE;
}

static PyObject *PLE_peek_last_item(PLE *self)
{
    if (self->last) {
        PyObject *tuple = PyTuple_New(2);
        Py_INCREF(self->last->key);
        PyTuple_SET_ITEM(tuple, 0, self->last->key);
        Py_INCREF(self->last->value);
        PyTuple_SET_ITEM(tuple, 1, self->last->value);
        return tuple;
    }
    else Py_RETURN_NONE;
}

static PyObject *PLE_keys(PLE *self) {return collect(self, get_key);}

static PyObject *get_value(Node *node)
{
    Py_INCREF(node->value);
    return node->value;
}

static PyObject *PLE_values(PLE *self) {return collect(self, get_value);}


static PyObject *get_item(Node *node)
{
    PyObject *tuple = PyTuple_New(2);
    Py_INCREF(node->key);
    PyTuple_SET_ITEM(tuple, 0, node->key);
    Py_INCREF(node->value);
    PyTuple_SET_ITEM(tuple, 1, node->value);
    return tuple;
}

static PyObject *PLE_items(PLE *self) {return collect(self, get_item);}

static PyObject *PLE_set_size(PLE *self, PyObject *args, PyObject *kwds)
{
    Py_ssize_t newSize;
    if (!PyArg_ParseTuple(args, "n", &newSize))  return NULL;

    if (newSize < 0) {
        PyErr_SetString(PyExc_ValueError, "Size should be a positive number");
        return NULL;
    }
    while (ple_length(self) > newSize)  ple_delete_last(self);

    self->size = newSize;
    Py_RETURN_NONE;
}

static PyObject *PLE_clear(PLE *self)
{
    Node *c = self->first;

    while (c) {
        Node* n = c;
        c = c->next;
        ple_remove_node(self, n);
    }
    PyDict_Clear(self->dict);

    Py_RETURN_NONE;
}


static PyObject *PLE_get_size(PLE *self) {return Py_BuildValue("i", self->size);}



/* Hack to implement "key in ple" */
static PySequenceMethods ple_as_sequence = {
    0,                             /* sq_length */
    0,                             /* sq_concat */
    0,                             /* sq_repeat */
    0,                             /* sq_item */
    0,                             /* sq_slice */
    0,                             /* sq_ass_item */
    0,                             /* sq_ass_slice */
    (objobjproc) PLE_seq_contains, /* sq_contains */
    0,                             /* sq_inplace_concat */
    0,                             /* sq_inplace_repeat */
};

static PyMethodDef PLE_methods[] = {
    {"__contains__", (PyCFunction)PLE_contains_key, METH_O | METH_COEXIST,
                    PyDoc_STR("L.__contains__(key) -> Check if key is there in L")},
    {"keys", (PyCFunction)PLE_keys, METH_NOARGS,
                    PyDoc_STR("L.keys() -> list of L's keys in MRU order")},
    {"values", (PyCFunction)PLE_values, METH_NOARGS,
                    PyDoc_STR("L.values() -> list of L's values in MRU order")},
    {"items", (PyCFunction)PLE_items, METH_NOARGS,
                    PyDoc_STR("L.items() -> list of L's items (key,value) in MRU order")},
    {"has_key",	(PyCFunction)PLE_contains, METH_VARARGS,
                    PyDoc_STR("L.has_key(key) -> Check if key is there in L")},
    {"get",	(PyCFunction)PLE_get, METH_VARARGS,
                    PyDoc_STR("L.get(key, instead) -> If L has key return its value, otherwise instead")},
    {"delete",	(PyCFunction)PLE_delete, METH_VARARGS,
                    PyDoc_STR("L.get(key, instead) -> If L has key return its value, otherwise instead")},
    {"set_size", (PyCFunction)PLE_set_size, METH_VARARGS,
                    PyDoc_STR("L.set_size() -> set size of LRU")},
    {"get_size", (PyCFunction)PLE_get_size, METH_NOARGS,
                    PyDoc_STR("L.get_size() -> get size of LRU")},
    {"clear", (PyCFunction)PLE_clear, METH_NOARGS,
                    PyDoc_STR("L.clear() -> clear LRU")},
    {"peek_first_item", (PyCFunction)PLE_peek_first_item, METH_NOARGS,
                    PyDoc_STR("L.peek_first_item() -> returns the MRU item (key,value) without changing key order")},
    {"peek_last_item", (PyCFunction)PLE_peek_last_item, METH_NOARGS,
                    PyDoc_STR("L.peek_last_item() -> returns the LRU item (key,value) without changing key order")},
    {"pop", (PyCFunction)PLE_pop, METH_NOARGS,
                    PyDoc_STR("L.pop() -> returns the LRU item (key,value) without changing key order")},
    {"update", (PyCFunction)PLE_update, METH_VARARGS | METH_KEYWORDS,
                    PyDoc_STR("L.update() -> update value for key in LRU")},
    {"put", (PyCFunction)PLE_put, METH_VARARGS | METH_KEYWORDS,
                    PyDoc_STR("L.append() -> append value for key in LRU")},
    {"append", (PyCFunction)PLE_append, METH_VARARGS | METH_KEYWORDS,
                    PyDoc_STR("L.append() -> append value for key in LRU")},

    {NULL,	NULL},
};

static PyObject*PLE_repr(PLE* self) {return PyObject_Repr(self->dict);}

static int PLE_init(PLE *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"size", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|n", kwlist, &self->size)) self->size = 0;


    if ((Py_ssize_t)self->size < 0) {
        PyErr_SetString(PyExc_ValueError, "Size should be a positive number");
        return -1;
    }
    self->dict = PyDict_New();
    self->first = self->last = NULL;
    return 0;
}

static void PLE_dealloc(PLE *self)
{
    if (self->dict) {
        PLE_clear(self);
        Py_DECREF(self->dict);
    }
    PyObject_Del((PyObject*)self);
}

PyDoc_STRVAR(ple_doc,
"LRU(size) -> new LRU dict that can store up to size elements\n"
"An LRU dict behaves like a standard dict, except that it stores only fixed\n"
"set of elements. Once the size overflows, it evicts least recently used\n"
"items. \n\n"
"Eg:\n"
">>> l = LRU(3)\n"
">>> for i in range(5):\n"
">>>   l[i] = str(i)\n"
">>> l.keys()\n"
"[2,3,4]\n\n"
"Note: An LRU(n) can be thought of as a dict that will have the most\n"
"recently accessed n items.\n");

static PyTypeObject PLEType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_ple.PLE",               /* tp_name */
    sizeof(PLE),             /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)PLE_dealloc, /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_compare */
    (reprfunc)PLE_repr,      /* tp_repr */
    0,                       /* tp_as_number */
    &ple_as_sequence,        /* tp_as_sequence */
    &PLE_as_mapping,         /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,      /* tp_flags */
    ple_doc,                 /* tp_doc */
    0,                       /* tp_traverse */
    0,                       /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    PLE_methods,             /* tp_methods */
    0,                       /* tp_members */
    0,                       /* tp_getset */
    0,                       /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)PLE_init,      /* tp_init */
    0,                       /* tp_alloc */
    0,                       /* tp_new */
};


static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_ple",            /* m_name */
    ple_doc,          /* m_doc */
    -1,               /* m_size */
    NULL,             /* m_methods */
    NULL,             /* m_reload */
    NULL,             /* m_traverse */
    NULL,             /* m_clear */
    NULL,             /* m_free */
  };


static PyObject *moduleinit(void) {
    PyObject *m;
    NodeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&NodeType) < 0) return NULL;
    PLEType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PLEType) < 0) return NULL;
    m = PyModule_Create(&moduledef);
    if (m == NULL) return NULL;
    Py_INCREF(&NodeType);
    Py_INCREF(&PLEType);
    PyModule_AddObject(m, "PLE", (PyObject *) &PLEType);
    return m;
}

PyMODINIT_FUNC PyInit__ple(void) {return moduleinit();}
