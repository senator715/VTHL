#include "link.h"
#include "../hook.h"

static LPCWSTR teststr = L"Hijack by VTHL";

//https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxexw
static decltype(&MessageBoxExW) trp_original = nullptr;
int __stdcall MessageBoxExW_hook(
  HWND   hWnd,
  LPCWSTR lpText,
  LPCWSTR lpCaption,
  UINT   uType,
  WORD   wLanguageId
){
  printf("VTHL Hijack %S\n", lpText);
  lpText = teststr;
  trp_original(hWnd, lpText, lpCaption, uType, wLanguageId);
  return 1337;
}

i32 main(i32 argc, const i8 *argv[]) {
  void* p = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxExW");
  trp_original = vthl_hook(p,MessageBoxExW_hook);

  system("pause");

  MessageBoxExW(nullptr, L"test", L"test", 0, 0);

  system("pause");

  vthl_unhook(trp_original);
  MessageBoxExW(nullptr, L"test", L"test", 0, 0);

  system("pause");

  return 0;
}
