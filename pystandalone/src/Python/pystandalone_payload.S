#ifdef __APPLE__
    .section __PYSTANDALONE,__pystandalone,regular,no_dead_strip
#else
    .section .pystandalone,"a",@progbits
#endif
    .globl _binary_pystandalone_start
_binary_pystandalone_start:
    .space 4*1024*1024,0
    .globl _binary_pystandalone_end
_binary_pystandalone_end:
