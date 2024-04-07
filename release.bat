cls
del *.obj
del *.dll
del *.ilk
del *.pdb
cl /LD /EHsc /nologo /D "NDEBUG" /O2 ravenhack.cpp /Z7 /link /DEBUG:NONE
