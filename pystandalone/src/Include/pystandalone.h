#ifndef Py_PYSTANDALONE_H
#define Py_PYSTANDALONE_H
#ifdef __cplusplus
extern "C" {
#endif

#define PYSTANDALONE_LIBRARY_ZIP              0
#define PYSTANDALONE_BOOTSTRAP_ZIP            1
#define PYSTANDALONE_PAYLOAD_ZIP              2

void PyStandalone_Init(void);
void PyStandalone_Install(void);
PyObject* PyStandalone_GetZip(unsigned int idx);
unsigned int PyStandalone_HasLibrary(void);
unsigned int PyStandalone_HasBootstrap(void);
unsigned int PyStandalone_HasPayload(void);

#ifdef __cplusplus
}
#endif
#endif
