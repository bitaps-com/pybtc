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

static void node_dealloc(Node* self) {
    Py_DECREF(self->key);
    Py_DECREF(self->value);
    PyObject_Del((PyObject*)self);
}

static PyObject*node_repr(Node* self) {return PyObject_Repr(self->value);}

static PyTypeObject NodeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "cache.Node",              /* tp_name */
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
} CACHE;

static Py_ssize_t cache_length(CACHE *self) {return PyDict_Size(self->dict);}


static void cache_remove_node(CACHE *self, Node* node) {
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

static void cache_add_node_at_head(CACHE *self, Node* node) {
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

static void cache_add_node_at_tail(CACHE *self, Node* node) {
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

static void cache_delete_last(CACHE *self) {
    Node* n = self->last;
    if (!self->last)  return;
    cache_remove_node(self, n);
    PyDict_DelItem(self->dict, n->key);
}

static int cache_append(CACHE *self, PyObject *key, PyObject *value) {
    int res = 0;
    Node *node = GET_NODE(self->dict, key);
    PyErr_Clear();
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
                if (self->size > 0 && cache_length(self) > self->size) cache_delete_last(self);
                cache_add_node_at_tail(self, node);
            }
        }
    } else {

        if (PUT_NODE(self->dict, key, NULL) == 0)  cache_remove_node(self, node);
    }

    Py_XDECREF(node);
    return res;
}

static PyObject *cache_contains_key(CACHE *self, PyObject *key) {
    if (PyDict_Contains(self->dict, key)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static int cache_seq_contains(CACHE *self, PyObject *key) {return PyDict_Contains(self->dict, key);}

static PyObject *collect(CACHE *self, PyObject * (*getterfunc)(Node *)) {
    register PyObject *v;
    Node *curr;
    int i;
    v = PyList_New(cache_length(self));
    if (v == NULL)
        return NULL;
    curr = self->first;
    i = 0;

    while (curr) {
        PyList_SET_ITEM(v, i++, getterfunc(curr));
        curr = curr->next;
    }

    return v;
}

static PyObject *get_key(Node *node) {
    Py_INCREF(node->key);
    return node->key;
}

static PyObject *get_value(Node *node) {
    Py_INCREF(node->value);
    return node->value;
}

static PyObject *get_item(Node *node) {
    PyObject *tuple = PyTuple_New(2);
    Py_INCREF(node->key);
    PyTuple_SET_ITEM(tuple, 0, node->key);
    Py_INCREF(node->value);
    PyTuple_SET_ITEM(tuple, 1, node->value);
    return tuple;
}



/* cache methods */

static PyObject *CACHE_keys(CACHE *self) {return collect(self, get_key);}

static PyObject *CACHE_values(CACHE *self) {return collect(self, get_value);}

static PyObject *CACHE_items(CACHE *self) {return collect(self, get_item);}

static PyObject *CACHE_contains(CACHE *self, PyObject *args) {
    PyObject *key;
    if (!PyArg_ParseTuple(args, "O", &key)) return NULL;

    return cache_contains_key(self, key);
}

static PyObject *CACHE_delete(CACHE *self, PyObject *args) {
    PyObject *key;
    PyObject *instead = NULL;
    if (!PyArg_ParseTuple(args, "O|O", &key, &instead)) return NULL;
    Node *node = GET_NODE(self->dict, key);

    if (!node) {
       if (!instead) {
       Py_XDECREF(node);
       Py_RETURN_NONE;
       }

       Py_INCREF(instead);
       Py_XDECREF(node);
       return instead;
    }
    PyObject *return_value = Py_BuildValue("O", node->value);
    cache_remove_node(self, node);
    PyDict_DelItem(self->dict, node->key);
    Py_XDECREF(node);
    return return_value;
}

static PyObject *CACHE_set_size(CACHE *self, PyObject *args, PyObject *kwds) {
    Py_ssize_t newSize;
    if (!PyArg_ParseTuple(args, "n", &newSize))  return NULL;

    if (newSize < 0) {
        PyErr_SetString(PyExc_ValueError, "Size should be a positive number");
        return NULL;
    }
    while (cache_length(self) > newSize)  cache_delete_last(self);

    self->size = newSize;
    Py_RETURN_NONE;
}

static PyObject *CACHE_get_size(CACHE *self) {return Py_BuildValue("i", self->size);}

static PyObject *CACHE_clear(CACHE *self) {
    Node *c = self->first;

    while (c) {
        Node* n = c;
        c = c->next;
        cache_remove_node(self, n);
    }
    PyDict_Clear(self->dict);

    Py_RETURN_NONE;
}

static PyObject *CACHE_peek_first_item(CACHE *self) {
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

static PyObject *CACHE_peek_last_item(CACHE *self) {
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

static PyObject *CACHE_pop(CACHE *self) {
    if (self->last) {
        PyObject *tuple = PyTuple_New(2);
        Py_INCREF(self->last->key);
        PyTuple_SET_ITEM(tuple, 0, self->last->key);
        Py_INCREF(self->last->value);
        PyTuple_SET_ITEM(tuple, 1, self->last->value);
        Node* n = self->last;
        cache_remove_node(self, n);
        PyDict_DelItem(self->dict, n->key);
        return tuple;
    }
    else Py_RETURN_NONE;
}

static PyObject *CACHE_append(CACHE *self, PyObject *args, PyObject *kwargs) {
	PyObject *key, *value;
	PyObject *arg = NULL;
	Py_ssize_t pos = 0;

	if ((PyArg_ParseTuple(args, "|O", &arg))) {
		if (arg && PyDict_Check(arg)) {
			while (PyDict_Next(arg, &pos, &key, &value))
				cache_append(self, key, value);
		}
	}

	if (kwargs != NULL && PyDict_Check(kwargs)) {
		while (PyDict_Next(kwargs, &pos, &key, &value))
			cache_append(self, key, value);
	}

	Py_RETURN_NONE;
}



/* MRU - Most Recently Used */

static PyObject *mru_subscript(CACHE *self, register PyObject *key) {
    Node *node = GET_NODE(self->dict, key);
    if (!node) return NULL;

    Py_INCREF(node->value);
    Py_DECREF(node);
    return node->value;
}

static int mru_ass_sub(CACHE *self, PyObject *key, PyObject *value) {
    int res = 0;
    Node *node = GET_NODE(self->dict, key);
    PyErr_Clear();
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
                if (self->size > 0 && cache_length(self) > self->size) cache_delete_last(self);
                cache_add_node_at_head(self, node);
            }
        }
    } else {
        if (PUT_NODE(self->dict, key, NULL) == 0)  cache_remove_node(self, node);
    }

    Py_XDECREF(node);
    return res;
}

static PyMappingMethods MRU_as_mapping = {
    (lenfunc)cache_length,        /*mp_length*/
    (binaryfunc)mru_subscript,  /*mp_subscript*/
    (objobjargproc)mru_ass_sub, /*mp_ass_subscript*/
};



static PyObject *MRU_get(CACHE *self, PyObject *args) {
    PyObject *key;
    PyObject *instead = NULL;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "O|O", &key, &instead)) return NULL;

    result = mru_subscript(self, key);
    PyErr_Clear();  /* GET_NODE sets an exception on miss. Shut it up. */
    if (result) return result;

    if (!instead) { Py_RETURN_NONE; }

    Py_INCREF(instead);
    return instead;
}

static PyObject *MRU_update(CACHE *self, PyObject *args, PyObject *kwargs) {
	PyObject *key, *value;
	PyObject *arg = NULL;
	Py_ssize_t pos = 0;

	if ((PyArg_ParseTuple(args, "|O", &arg))) {
		if (arg && PyDict_Check(arg)) {
			while (PyDict_Next(arg, &pos, &key, &value))
				mru_ass_sub(self, key, value);
		}
	}

	if (kwargs != NULL && PyDict_Check(kwargs)) {
		while (PyDict_Next(kwargs, &pos, &key, &value))
			mru_ass_sub(self, key, value);
	}

	Py_RETURN_NONE;
}




/* LRU - Last Recently Used */



static PyObject * lru_subscript(CACHE *self, register PyObject *key) {
    Node *node = GET_NODE(self->dict, key);
    if (!node)  return NULL;

    /* We don't need to move the node when it's already self->first. */
    if (node != self->first) {
        cache_remove_node(self, node);
        cache_add_node_at_head(self, node);
    }

    Py_INCREF(node->value);
    Py_DECREF(node);
    return node->value;
}

static PyObject *LRU_get(CACHE *self, PyObject *args) {
    PyObject *key;
    PyObject *instead = NULL;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "O|O", &key, &instead)) return NULL;

    result = lru_subscript(self, key);
    PyErr_Clear();  /* GET_NODE sets an exception on miss. Shut it up. */
    if (result) return result;

    if (!instead) { Py_RETURN_NONE; }

    Py_INCREF(instead);
    return instead;
}

static int lru_ass_sub(CACHE *self, PyObject *key, PyObject *value)  {
    int res = 0;
    Node *node = GET_NODE(self->dict, key);
    PyErr_Clear();
    if (value) {
        if (node) {
            Py_INCREF(value);
            Py_DECREF(node->value);
            node->value = value;

            cache_remove_node(self, node);
            cache_add_node_at_head(self, node);
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
                if (self->size > 0 && cache_length(self) > self->size) cache_delete_last(self);
                cache_add_node_at_head(self, node);
            }
        }
    } else {
        if (PUT_NODE(self->dict, key, NULL) == 0)  cache_remove_node(self, node);
    }

    Py_XDECREF(node);
    return res;
}

static PyMappingMethods LRU_as_mapping = {
    (lenfunc)cache_length,        /*mp_length*/
    (binaryfunc)lru_subscript,  /*mp_subscript*/
    (objobjargproc)lru_ass_sub, /*mp_ass_subscript*/
};

static PyObject *LRU_update(CACHE *self, PyObject *args, PyObject *kwargs) {
	PyObject *key, *value;
	PyObject *arg = NULL;
	Py_ssize_t pos = 0;

	if ((PyArg_ParseTuple(args, "|O", &arg))) {
		if (arg && PyDict_Check(arg)) {
			while (PyDict_Next(arg, &pos, &key, &value))
				lru_ass_sub(self, key, value);
		}
	}

	if (kwargs != NULL && PyDict_Check(kwargs)) {
		while (PyDict_Next(kwargs, &pos, &key, &value))
			lru_ass_sub(self, key, value);
	}

	Py_RETURN_NONE;
}









static int cache_init(CACHE *self, PyObject *args, PyObject *kwds) {
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

static void cache_dealloc(CACHE *self) {
    if (self->dict) {
        CACHE_clear(self);
        Py_DECREF(self->dict);
    }
    PyObject_Del((PyObject*)self);
}

static PySequenceMethods cache_as_sequence = {
    0,                             /* sq_length */
    0,                             /* sq_concat */
    0,                             /* sq_repeat */
    0,                             /* sq_item */
    0,                             /* sq_slice */
    0,                             /* sq_ass_item */
    0,                             /* sq_ass_slice */
    (objobjproc) cache_seq_contains,/* sq_contains */
    0,                             /* sq_inplace_concat */
    0,                             /* sq_inplace_repeat */
};

static PyObject*cache_repr(CACHE* self) {return PyObject_Repr(self->dict);}








static PyMethodDef MRU_methods[] = {
    {"__contains__", (PyCFunction)cache_contains_key, METH_O | METH_COEXIST, "L.__contains__(key) -> Check if key is there in L"},
    {"keys", (PyCFunction)CACHE_keys, METH_NOARGS, "L.keys() -> list of L's keys in MRU order"},
    {"values", (PyCFunction)CACHE_values, METH_NOARGS, "L.values() -> list of L's values in MRU order"},
    {"items", (PyCFunction)CACHE_items, METH_NOARGS, "L.items() -> list of L's items (key,value) in MRU order"},
    {"has_key",	(PyCFunction)CACHE_contains, METH_VARARGS, "L.has_key(key) -> Check if key is there in L"},
    {"get",	(PyCFunction)MRU_get, METH_VARARGS, "L.get(key, instead) -> If L has key return its value, otherwise instead"},
    {"delete",	(PyCFunction)CACHE_delete, METH_VARARGS, "L.delete(key, instead) -> If L has key return its value, otherwise instead"},
    {"set_size", (PyCFunction)CACHE_set_size, METH_VARARGS, "L.set_size() -> set size of MRU"},
    {"get_size", (PyCFunction)CACHE_get_size, METH_NOARGS, "L.get_size() -> get size of MRU"},
    {"clear", (PyCFunction)CACHE_clear, METH_NOARGS, "L.clear() -> clear MRU"},
    {"peek_first_item", (PyCFunction)CACHE_peek_first_item, METH_NOARGS, "L.peek_first_item() -> returns the MRU item (key,value) without changing key order"},
    {"peek_last_item", (PyCFunction)CACHE_peek_last_item, METH_NOARGS, "L.peek_last_item() -> returns the MRU item (key,value) without changing key order"},
    {"pop", (PyCFunction)CACHE_pop, METH_NOARGS, "L.pop() -> returns the MRU item (key,value) without changing key order"},
    {"update", (PyCFunction)MRU_update, METH_VARARGS | METH_KEYWORDS, "L.update() -> update value for key in MRU"},
    {"append", (PyCFunction)CACHE_append, METH_VARARGS | METH_KEYWORDS, "L.append() -> append value for key in MRU"},
    {NULL,	NULL},
};

static PyMethodDef LRU_methods[] = {
    {"__contains__", (PyCFunction)cache_contains_key, METH_O | METH_COEXIST, "L.__contains__(key) -> Check if key is there in L"},
    {"keys", (PyCFunction)CACHE_keys, METH_NOARGS, "L.keys() -> list of L's keys in LRU order"},
    {"values", (PyCFunction)CACHE_values, METH_NOARGS, "L.values() -> list of L's values in LRU order"},
    {"items", (PyCFunction)CACHE_items, METH_NOARGS, "L.items() -> list of L's items (key,value) in LRU order"},
    {"has_key",	(PyCFunction)CACHE_contains, METH_VARARGS, "L.has_key(key) -> Check if key is there in L"},
    {"get",	(PyCFunction)LRU_get, METH_VARARGS, "L.get(key, instead) -> If L has key return its value, otherwise instead"},
    {"delete",	(PyCFunction)CACHE_delete, METH_VARARGS, "L.delete(key, instead) -> If L has key return its value, otherwise instead"},
    {"set_size", (PyCFunction)CACHE_set_size, METH_VARARGS, "L.set_size() -> set size of LRU"},
    {"get_size", (PyCFunction)CACHE_get_size, METH_NOARGS, "L.get_size() -> get size of LRU"},
    {"clear", (PyCFunction)CACHE_clear, METH_NOARGS, "L.clear() -> clear LRU"},
    {"peek_first_item", (PyCFunction)CACHE_peek_first_item, METH_NOARGS, "L.peek_first_item() -> returns the LRU item (key,value) without changing key order"},
    {"peek_last_item", (PyCFunction)CACHE_peek_last_item, METH_NOARGS, "L.peek_last_item() -> returns the LRU item (key,value) without changing key order"},
    {"pop", (PyCFunction)CACHE_pop, METH_NOARGS, "L.pop() -> returns the LRU item (key,value) without changing key order"},
    {"update", (PyCFunction)LRU_update, METH_VARARGS | METH_KEYWORDS, "L.update() -> update value for key in LRU"},
    {"append", (PyCFunction)CACHE_append, METH_VARARGS | METH_KEYWORDS, "L.append() -> append value for key in LRU"},
    {NULL,	NULL},
};


static PyTypeObject MRUType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "cache_strategies.MRU",               /* tp_name */
    sizeof(CACHE),             /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)cache_dealloc, /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_compare */
    (reprfunc)cache_repr,      /* tp_repr */
    0,                       /* tp_as_number */
    &cache_as_sequence,        /* tp_as_sequence */
    &MRU_as_mapping,         /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,      /* tp_flags */
    0,                       /* tp_doc */
    0,                       /* tp_traverse */
    0,                       /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    MRU_methods,             /* tp_methods */
    0,                       /* tp_members */
    0,                       /* tp_getset */
    0,                       /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)cache_init,      /* tp_init */
    0,                       /* tp_alloc */
    0,                       /* tp_new */
};

static PyTypeObject LRUType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "cache_strategies.LRU",               /* tp_name */
    sizeof(CACHE),             /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)cache_dealloc, /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_compare */
    (reprfunc)cache_repr,      /* tp_repr */
    0,                       /* tp_as_number */
    &cache_as_sequence,        /* tp_as_sequence */
    &LRU_as_mapping,         /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,      /* tp_flags */
    0,                       /* tp_doc */
    0,                       /* tp_traverse */
    0,                       /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    LRU_methods,             /* tp_methods */
    0,                       /* tp_members */
    0,                       /* tp_getset */
    0,                       /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)cache_init,      /* tp_init */
    0,                       /* tp_alloc */
    0,                       /* tp_new */
};





static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "cache_strategies",            /* m_name */
    "cache strategies",          /* m_doc */
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
    MRUType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&MRUType) < 0) return NULL;
    LRUType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&LRUType) < 0) return NULL;
    m = PyModule_Create(&moduledef);
    if (m == NULL) return NULL;
    Py_INCREF(&NodeType);
    Py_INCREF(&MRUType);
    Py_INCREF(&LRUType);
    PyModule_AddObject(m, "MRU", (PyObject *) &MRUType);
    PyModule_AddObject(m, "LRU", (PyObject *) &LRUType);
    return m;
}

PyMODINIT_FUNC PyInit_cache_strategies(void) {return moduleinit();}
