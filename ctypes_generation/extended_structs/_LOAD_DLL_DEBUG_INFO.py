# typedef struct _LOAD_DLL_DEBUG_INFO {
#     HANDLE hFile;
#     LPVOID lpBaseOfDll;
#     DWORD dwDebugInfoFileOffset;
#     DWORD nDebugInfoSize;
#     LPVOID lpImageName;
#     WORD fUnicode;
# } LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;

class _LOAD_DLL_DEBUG_INFO(_LOAD_DLL_DEBUG_INFO):
    def hello(self):
        return "hello"