#pragma once

#include "hde/hde.h"
#include <windows.h>

// type definitions
typedef char i8;
typedef short i16;
typedef int i32;
typedef long long i64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long ul64;
typedef unsigned long long u64;

#define VTHL_DEBUG
#define VTHL_MAX_HOOKS 128

#if defined(__x86_64__)
typedef u64 uptr;
#define VTHL_HDE hde64s
#define VTHL_HDE_DISASM hde64_disasm
#define VTHL_MIN_LEN 14
#else
typedef u32 uptr;
#define VTHL_HDE hde32s
#define VTHL_HDE_DISASM hde32_disasm
#define VTHL_MIN_LEN 5
#endif

// memory management wrappers
static void* vthl_virtual_alloc(void* address, ul64 size, u32 alloc_type, u32 protect){
  return VirtualAlloc(address, size, alloc_type, protect);
}

static bool vthl_virtual_free(void* address, ul64 size, u32 free_type){
  return VirtualFree(address, size, free_type);
}

static bool vthl_virtual_protect(void* address, ul64 size, u32 new_protect, u32* old_protect){
  return VirtualProtect(address, size, new_protect, old_protect);
}

// memory set and copy wrappers
static void* vthl_memset(void* ptr, i32 value, ul64 num){
  return memset(ptr, value, num);
}

static void* vthl_memcpy(void* dest, const void* src, ul64 num){
  return memcpy(dest, src, num);
}

// logging utility
#if defined(VTHL_DEBUG)
static i32 vthl_printf(const char* format, ...){
  va_list args;
  va_start(args, format);
  i32 ret = vprintf(format, args);
  va_end(args);
  return ret;
}
#else
#define vthl_printf(...) {}
#endif

// hook data structure
struct vthl_hook_data{
  void* target_func;      // target function to hook
  void* trampoline;       // trampoline for original function
  u8 original_bytes[16];  // original bytes to restore later
  u8 original_length;     // length of original bytes
};

static vthl_hook_data vthl_hook_data_array[VTHL_MAX_HOOKS];
static i32 vthl_hook_data_count = 0;

// hook function
static void* vthl_hook(void* target_func, void* dest_func){
  vthl_printf("vthl_hook: hooking function (target_func: %p to dest_func: %p)\n", target_func, dest_func);

  if(!target_func || !dest_func){
    vthl_printf("[ERROR] vthl_hook: invalid target or destination function.\n");
    return nullptr;
  }

  if(vthl_hook_data_count >= VTHL_MAX_HOOKS){
    vthl_printf("[ERROR] vthl_hook: maximum number of hooks reached.\n");
    return nullptr;
  }

  // calculate instruction length to overwrite
  u8 len = 0;
  VTHL_HDE h;
  for(;len < VTHL_MIN_LEN;)
    len += VTHL_HDE_DISASM((uptr)target_func + len, &h);

  vthl_hook_data hook_data = {target_func, nullptr, {0}, len};
  vthl_memcpy(hook_data.original_bytes, target_func, len);

  // allocate memory for trampoline
  void* trp = vthl_virtual_alloc(nullptr, len + (sizeof(uptr) == 8 ? 14 : 5), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if(!trp){
    vthl_printf("[ERROR] vthl_hook: failed to allocate memory for trampoline.\n");
    return nullptr;
  }

  vthl_printf("vthl_hook: trampoline created at address %p\n", trp);
  vthl_memcpy(trp, target_func, len);

  // set up trampoline jump back to original function
#if defined(_M_X64) || defined(__x86_64__)
  *(u16*)((uptr)trp + len) = 0x25FF;
  *(u64*)((uptr)trp + len + 6) = (uptr)target_func + len;
#else
  *(u8*)((uptr)trp + len) = 0xE9;
  *(i32*)((uptr)trp + len + 1) = (uptr)target_func + len - ((uptr)trp + len + 5);
#endif

  // protect trampoline memory
  u32 old_protect;
  if(!vthl_virtual_protect(trp, len + (sizeof(uptr) == 8 ? 14 : 5), PAGE_EXECUTE_READ, &old_protect)){
    vthl_printf("[ERROR] vthl_hook: failed to protect trampoline memory.\n");
    return nullptr;
  }

  // overwrite target function to jump to destination function
  if(!vthl_virtual_protect(target_func, len, PAGE_EXECUTE_WRITECOPY, &old_protect)){
    vthl_printf("[ERROR] vthl_hook: failed to change memory protection for target function.\n");
    return nullptr;
  }
  vthl_memset(target_func, 0x0, len);

#if defined(_M_X64) || defined(__x86_64__)
  *(u16*)((uptr)target_func) = 0x25FF;
  *(u64*)((uptr)target_func + 6) = (uptr)dest_func;
#else
  *(u8*)((uptr)target_func) = 0xE9;
  *(i32*)((uptr)target_func + 1) = (uptr)dest_func - ((uptr)target_func + 5);
#endif

  // restore protection on target function
  vthl_virtual_protect(target_func, len, old_protect, &old_protect);
  hook_data.trampoline = trp;
  vthl_hook_data_array[vthl_hook_data_count++] = hook_data;
  return trp;
}

// unhook function
static bool vthl_unhook(void* func){
  vthl_printf("vthl_unhook: unhooking function (func: %p)\n", func);
  for(i32 i = 0; i < vthl_hook_data_count; ++i){
    if(vthl_hook_data_array[i].target_func == func || vthl_hook_data_array[i].trampoline == func){
      // restore original bytes to target function
      u32 old_protect;
      vthl_virtual_protect(vthl_hook_data_array[i].target_func, vthl_hook_data_array[i].original_length, PAGE_EXECUTE_WRITECOPY, &old_protect);
      vthl_memcpy(vthl_hook_data_array[i].target_func, vthl_hook_data_array[i].original_bytes, vthl_hook_data_array[i].original_length);
      vthl_virtual_protect(vthl_hook_data_array[i].target_func, vthl_hook_data_array[i].original_length, old_protect, &old_protect);

      // free trampoline memory
      vthl_virtual_free(vthl_hook_data_array[i].trampoline, 0, MEM_RELEASE);
      vthl_hook_data_array[i] = vthl_hook_data_array[--vthl_hook_data_count];
      return true;
    }
  }
  return false;
}