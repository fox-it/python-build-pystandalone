/* pystandalone interpreter code */
/* Author: Erik Schamper <1254028+Schamper@users.noreply.github.com> */

#include "Python.h"

#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
/* 3.10 only: add an anchor for the payload data so it gets linked in */
extern const char _pystandalone_payload_start __asm__("_binary_pystandalone_start");
extern const char _pystandalone_payload_end __asm__("_binary_pystandalone_end");
static const void * const _pystandalone_anchor[] __attribute__((used)) = {
    (const void *)&_pystandalone_payload_start,
    (const void *)&_pystandalone_payload_end,
};
#elif (defined MS_WINDOWS)
#include <windows.h>
#else
extern const unsigned char _binary_pystandalone_start[];
extern const unsigned char _binary_pystandalone_end[];
#endif

/* Linked list for tracking embedded zip files */

typedef struct _PyStandalone_Zip {
    unsigned int idx;
    unsigned char *buf;
    unsigned int size;
    struct _PyStandalone_Zip *next;
} PyStandalone_Zip;

static PyStandalone_Zip *pystandalone_zips = NULL;

/* Internal functions for pystandalone zips */

static unsigned int
get_uint32(const unsigned char *buf)
{
    unsigned int x;
    x =  buf[0];
    x |= (unsigned int)buf[1] <<  8;
    x |= (unsigned int)buf[2] << 16;
    x |= (unsigned int)buf[3] << 24;
    return x;
}

static void
register_zip(unsigned int idx, unsigned char *buf, unsigned int size)
{
    PyStandalone_Zip *cur;
    PyStandalone_Zip *item = (PyStandalone_Zip *)malloc(sizeof(PyStandalone_Zip));

    item->idx = idx;
    item->buf = buf;
    item->size = size;
    item->next = NULL;

    if (pystandalone_zips) {
        cur = pystandalone_zips;
        while (cur->next) {
            cur = cur->next;
        }
        cur->next = item;
    }
    else {
        pystandalone_zips = item;
    }
}

static PyStandalone_Zip *
get_zip(unsigned int idx)
{
    PyStandalone_Zip *cur;

    if (pystandalone_zips == NULL) {
        return NULL;
    }

    cur = pystandalone_zips;

    do {
        if (cur->idx == idx) {
            return cur;
        }
        cur = cur->next;
    }
    while (cur != NULL);

    return NULL;
}

static PyObject *
create_zipimporter(char *name, unsigned int idx)
{
    PyObject *memoryview = PyStandalone_GetZip(idx);
    if (memoryview == NULL) {
        return NULL;
    }

    PyObject *args = Py_BuildValue("sO", name, memoryview);
    if (args == NULL) {
        return NULL;
    }

    int res = PyImport_ImportFrozenModule("zipimport");
    if (res != 1) {
        return NULL;
    }

    PyObject *zipimport = PyImport_ImportModule("zipimport");
    if (zipimport == NULL) {
        return NULL;
    }

    PyObject *zipimporter = PyObject_GetAttrString(zipimport, "metazipimporter");
    Py_DECREF(zipimport);
    if (zipimporter == NULL) {
        return NULL;
    }

    PyObject *result = PyObject_CallObject(zipimporter, args);
    Py_DECREF(zipimporter);
    if (result == NULL) {
        return NULL;
    }

    return result;
}

void
PyStandalone_Init(void)
{
    unsigned int idx = 0, size = 0;
#ifdef __APPLE__
    unsigned long sect_size;
    unsigned char *buf = getsectiondata(&_mh_execute_header, "__PYSTANDALONE", "__pystandalone", &sect_size);
    unsigned char *end = buf + sect_size;
    if (buf == NULL) {
        return;
    }
#elif (defined MS_WINDOWS)
    HRSRC res = FindResource(NULL, MAKEINTRESOURCE(1), RT_RCDATA);
    if (res == NULL) {
        return;
    }

    unsigned char *buf = LoadResource(NULL, res);
    DWORD resource_size = SizeofResource(NULL, res);
    unsigned char *end = buf + resource_size;
#else
    unsigned char *buf = (unsigned char *)(&_binary_pystandalone_start);
    unsigned char *end = (unsigned char *)(&_binary_pystandalone_end);
#endif

    while (buf < end)
    {
        size = get_uint32(buf);
        if (size == 0) {
            break;
        }
        buf += 4;

        if (buf + size <= end) {
            register_zip(idx, buf, size);
        }

        buf += size;
        idx += 1;
    }
}

void
PyStandalone_Install(void)
{
    PyObject *meta_path = PySys_GetObject("meta_path");

    PyObject *library_importer = create_zipimporter("<library>", PYSTANDALONE_LIBRARY_ZIP);
    if (library_importer != NULL) {
        PyList_Append(meta_path, library_importer);
    }

    PyObject *bootstrap_importer = create_zipimporter("<bootstrap>", PYSTANDALONE_BOOTSTRAP_ZIP);
    if (bootstrap_importer != NULL) {
        PyList_Append(meta_path, bootstrap_importer);
    }
}

PyObject *
PyStandalone_GetZip(unsigned int idx)
{
    PyStandalone_Zip *zip = get_zip(idx);
    if (zip == NULL) {
        return NULL;
    }

    return PyMemoryView_FromMemory((char *)zip->buf, zip->size, PyBUF_READ);
}

unsigned int
PyStandalone_HasLibrary(void)
{
    return get_zip(PYSTANDALONE_LIBRARY_ZIP) != NULL;
}

unsigned int
PyStandalone_HasBootstrap(void)
{
    return get_zip(PYSTANDALONE_BOOTSTRAP_ZIP) != NULL;
}

unsigned int
PyStandalone_HasPayload(void)
{
    return get_zip(PYSTANDALONE_PAYLOAD_ZIP) != NULL;
}
