#ifndef __IDALDR_H__
#define __IDALDR_H__

#include <ida.hpp>
#include <fpro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <srarea.hpp>
#include <fixup.hpp>
#include <entry.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>

//----------------------------------

#define CLASS_CODE    "CODE"
#define NAME_CODE     ".text"
#define CLASS_DATA    "DATA"
#define CLASS_CONST   "CONST"
#define NAME_DATA     ".data"
#define CLASS_BSS     "BSS"
#define NAME_BSS      ".bss"
#define NAME_EXTERN   "extern"
#define NAME_COMMON   "common"
#define NAME_ABS      "abs"
#define NAME_UNDEF    "UNDEF"
#define CLASS_STACK   "STACK"
#define CLASS_RES16   "RESOURCE"
#define LDR_NODE      "$ IDALDR node for ids loading $"
#define LDR_INFO_NODE "$ IDALDR node for unload $"

//----------------------------------
inline uchar readchar(linput_t *li)
{
  uchar x;
  lread(li, &x, sizeof(x));
  return x;
}

//----------------------------------
inline uint16 readshort(linput_t *li)
{
  uint16 x;
  lread(li, &x, sizeof(x));
  return x;
}

//----------------------------------
inline uint32 readlong(linput_t *li)
{
  uint32 x;
  lread(li, &x, sizeof(x));
  return x;
}

inline uint32 mf_readlong(linput_t *li)  { return swap32(readlong(li)); }
inline uint16 mf_readshort(linput_t *li) { return swap16(readshort(li)); }

// each loader must declare and export this symbol:
idaman loader_t ida_module_data LDSC;

#endif // __IDALDR_H__
