
#include "stdafx.h"
#include "idaldr.h"

#include <vector>

#pragma comment(lib, "ida")


typedef unsigned char u8;
typedef signed char s8;

typedef unsigned int u32;
typedef int s32;

typedef unsigned short u16;
typedef short s16;

typedef long long int  s64;
typedef unsigned long long int  u64;

typedef float f32;
typedef double f64;

typedef unsigned char           bit8;
typedef unsigned short          bit16;
typedef unsigned int            bit32;
typedef unsigned long long int  bit64;

struct NCCH_Header {
	u8 signature[0x100];
	u32 magic;
	u32 content_size;
	u8 partition_id[8];
	u16 maker_code;
	u16 version;
	u8 reserved_0[4];
	u8 program_id[8];
	u8 reserved_1[0x10];
	u8 logo_region_hash[0x20];
	u8 product_code[0x10];
	u8 extended_header_hash[0x20];
	u32 extended_header_size;
	u8 reserved_2[4];
	u8 flags[8];
	u32 plain_region_offset;
	u32 plain_region_size;
	u32 logo_region_offset;
	u32 logo_region_size;
	u32 exefs_offset;
	u32 exefs_size;
	u32 exefs_hash_region_size;
	u8 reserved_3[4];
	u32 romfs_offset;
	u32 romfs_size;
	u32 romfs_hash_region_size;
	u8 reserved_4[4];
	u8 exefs_super_block_hash[0x20];
	u8 romfs_super_block_hash[0x20];
};

struct ExeFs_SectionHeader {
    char name[8];
    u32 offset;
    u32 size;
};

struct ExeFs_Header {
    ExeFs_SectionHeader section[8];
    u8 reserved[0x80];
    u8 hashes[8][0x20];
};

struct storage_info_t
{
	bit64 exdataID;
	bit64 system_save_data_ids;
	bit64 stor_access_uniq_ids;
	bit8 fs_access_info[7];
	bit8 other_attr;
};

struct access_control_info_t
{
	// ARM11 local system caps
	bit64 programID;
	bit32 core_version;
	bit16 flag1_2;
	bit8 flag0;
	bit8 priority;
	bit16 resource_limit_desc[16];
	storage_info_t storage_info;
	bit8 service_access_control[32][8];
	bit64 ext_service_access_control[2];
	bit8 reserved_0[0xF];
	bit8 resource_limit_cat;

	// ARM11 kernel caps
	bit32 kern_caps_desc[28];
	bit8 reserved_1[0xF];

	// ARM9 Access Control
	u8 arm9_acc_ctrl_desc[0xF];
	u8 arm9_desc_version;
};

struct code_set_info_t
{
	bit32 offset;
	bit32 size_in_blocks;
	bit32 size_in_bytes;
};

struct exheader_t
{
	// system control info
	bit8 title[8];
	bit8 reserved_0[5];
	bit8 flag;
	code_set_info_t code;
	bit32 stack_size;
	code_set_info_t ro;
	bit32 reserved_1;
	code_set_info_t data;
	bit32 bss_size;
	bit64 modules[48];
	// - system info
	bit64 savedata_size;
	bit64 jumpID;
	bit8 reserved_2[0x30];
	access_control_info_t aci;
	bit8 signature [0x100];
	bit8 public_key[0x100];
	access_control_info_t aci_lim;
};


struct fw_sect_header_t
{
	u32 offset;
	u32 address;
	u32 size;
	u32 fw_type; // 0 - arm9, 1 = arm11
	char sha256[0x20];
};

struct firm_header_t
{
	u32 magic;
	u32 reserved1;
	u32 arm11_entry;
	u32 arm9_entry;
	char reserver2[0x30];
	fw_sect_header_t sections[4];
	char rsa[0x100];
};

const u32 kBlockSize = 0x200;

static inline u32 MakeMagic(char a, char b, char c, char d) {
	return a | b << 8 | c << 16 | d << 24;
}

static u32 LZSS_GetDecompressedSize(const u8* buffer, u32 size) {
	u32 offset_size = *(u32*)(buffer + size - 4);
	return offset_size + size;
}
static bool LZSS_Decompress(const u8* compressed, u32 compressed_size, u8* decompressed, u32 decompressed_size) {
	const u8* footer = compressed + compressed_size - 8;
	u32 buffer_top_and_bottom = *reinterpret_cast<const u32*>(footer);
	u32 out = decompressed_size;
	u32 index = compressed_size - ((buffer_top_and_bottom >> 24) & 0xFF);
	u32 stop_index = compressed_size - (buffer_top_and_bottom & 0xFFFFFF);

	memset(decompressed, 0, decompressed_size);
	memcpy(decompressed, compressed, compressed_size);

	while (index > stop_index) {
		u8 control = compressed[--index];

		for (unsigned i = 0; i < 8; i++) {
			if (index <= stop_index)
				break;
			if (index <= 0)
				break;
			if (out <= 0)
				break;

			if (control & 0x80) {
				// Check if compression is out of bounds
				if (index < 2)
					return false;
				index -= 2;

				u32 segment_offset = compressed[index] | (compressed[index + 1] << 8);
				u32 segment_size = ((segment_offset >> 12) & 15) + 3;
				segment_offset &= 0x0FFF;
				segment_offset += 2;

				// Check if compression is out of bounds
				if (out < segment_size)
					return false;

				for (unsigned j = 0; j < segment_size; j++) {
					// Check if compression is out of bounds
					if (out + segment_offset >= decompressed_size)
						return false;

					u8 data = decompressed[out + segment_offset];
					decompressed[--out] = data;
				}
			} else {
				// Check if compression is out of bounds
				if (out < 1)
					return false;
				decompressed[--out] = compressed[--index];
			}
			control <<= 1;
		}
	}
	return true;
}

class firm
{
public:
	bool load_header(linput_t*);
	void load_file(linput_t*);
private:
	firm_header_t fw;
};

bool firm::load_header(linput_t* li)
{
	u32 size = qlsize(li);
	if(size < sizeof(firm_header_t))
		return false;
	qlseek(li, 0);
	qlread(li, &fw, sizeof(firm_header_t));
	if (MakeMagic('F', 'I', 'R', 'M') != fw.magic)
		return false;
	return true;
}

void firm::load_file(linput_t* li)
{
	for(int i=0; i<4; ++i)
	{
		const fw_sect_header_t& section = fw.sections[i];
		if (section.offset == 0 && section.size == 0)
			continue;
		qlseek(li, section.offset);


		
		set_selector(i+1, 0);
		if(i==0)
		{
			add_segm(i+1, section.address, section.address + section.size , NAME_DATA, CLASS_DATA);
		} else
		{
			char name[0x20];
			qsnprintf(name, 0x20, ".text%d", i+1);
			add_segm(i+1, section.address, section.address + section.size , name, CLASS_CODE);
		}
		

		set_segm_addressing(getseg( section.address ), 1); // enable 32bit addressing
		file2base(li, section.offset, section.address, section.address + section.size, 0);
	}
}

class _3ds
{
public:
	_3ds(): ncch_offset(0) {}
	bool load_header(linput_t*);
	void load_file(linput_t*);
private:
	NCCH_Header	ncch_header;
	u32			ncch_offset;
	exheader_t	exh;
	ExeFs_Header exefs_header;
};


bool _3ds::load_header(linput_t* li)
{
	u32 size = qlsize(li);
	if(size < 0x4000)
		return false;
	qlseek(li, 0);
	qlread(li, &ncch_header, sizeof(ncch_header));

	if (MakeMagic('N', 'C', 'S', 'D') == ncch_header.magic) {
		ncch_offset = 0x4000;
		qlseek(li, ncch_offset);
		qlread(li, &ncch_header, sizeof(ncch_header));
	}
	u32 pos = qltell(li);
	if (MakeMagic('N', 'C', 'C', 'H') != ncch_header.magic)
		return false;
	return true;
}

void _3ds::load_file(linput_t* li)
{
	u32 pos = qltell(li);

	qlread(li, &exh, sizeof(exh));

	bool is_compressed = (exh.flag & 1) == 1;

	u32 exefs_offset = ncch_header.exefs_offset * kBlockSize;

	qlseek(li, exefs_offset + ncch_offset);

	qlread(li, &exefs_header, sizeof(exefs_header));

	std::vector<u8> code;

	for(u32 i = 0; i < 8; ++i)
	{
		const ExeFs_SectionHeader& section = exefs_header.section[i];
		if(0 == qstrcmp(section.name, ".code"))
		{
			u32 offset = section.offset + exefs_offset + sizeof(ExeFs_Header) +  ncch_offset;
			qlseek(li, offset);
			if(is_compressed)
			{
				std::vector<u8> temp;
				temp.resize(section.size);
				qlread(li, &temp[0], section.size);
				u32 decompressed_size = LZSS_GetDecompressedSize(&temp[0], section.size);
				code.resize(decompressed_size);
				bool rc = LZSS_Decompress(&temp[0], section.size, &code[0], decompressed_size);
				if(!rc)
					qexit(1);
			} else
			{
				code.resize(section.size);
				qlread(li, &code[0], section.size);
			}
			break;;
		}
	}

	bool aligned = code.size() >= (exh.code.size_in_bytes + exh.ro.size_in_bytes + exh.data.size_in_bytes); 
	u32 offset = 0;

	set_selector(1, 0);
	if (!add_segm(1, exh.code.offset, exh.code.offset + exh.code.size_in_blocks * 0x1000 , NAME_CODE, CLASS_CODE))
		qexit(1);
	set_segm_addressing(getseg( exh.code.offset ), 1); // enable 32bit addressing
	mem2base(&code[offset], exh.code.offset, exh.code.offset + exh.code.size_in_bytes, -1);

	offset = aligned ? exh.code.size_in_blocks * 0x1000 : exh.code.size_in_bytes;

	set_selector(2, 0);
	if (!add_segm(2, exh.ro.offset, exh.ro.offset + exh.ro.size_in_blocks * 0x1000 , ".ro", CLASS_CONST))
		qexit(1);
	mem2base(&code[offset], exh.ro.offset, exh.ro.offset + exh.ro.size_in_bytes, -1);

	set_selector(3, 0);
	if (!add_segm(3, exh.data.offset, exh.data.offset + exh.data.size_in_blocks * 0x1000 , NAME_DATA, CLASS_DATA))
		qexit(1);

	offset = aligned ? (exh.code.size_in_blocks + exh.ro.size_in_blocks) * 0x1000  : exh.code.size_in_bytes + exh.ro.size_in_bytes;
	
	mem2base(&code[offset], exh.data.offset, exh.data.offset + exh.data.size_in_bytes, -1);

	set_selector(4, 0);
	add_segm(4, (exh.data.offset + exh.data.size_in_blocks * 0x1000), (exh.data.offset + exh.data.size_in_blocks * 0x1000) + exh.bss_size, NAME_BSS, CLASS_BSS);


}



class cia
{
	
};

int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	if( n!= 0 )
		return 0;

	firm firm;
	if(firm.load_header(li))
	{
		qstrncpy(fileformatname, "Nintendo 3DS firmware dump", MAX_FILE_FORMAT_NAME);
		set_processor_type("ARM", SETPROC_ALL|SETPROC_FATAL);
		return 1 | ACCEPT_FIRST;
	}

	_3ds _3ds;
	if(_3ds.load_header(li)) {
		qstrncpy(fileformatname, "Nintendo 3DS game dump", MAX_FILE_FORMAT_NAME);
		set_processor_type("ARM", SETPROC_ALL|SETPROC_FATAL);
		return 1 | ACCEPT_FIRST;
	} 
	return 0;
	
	
}


void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
	if(qstrcmp(fileformatname, "Nintendo 3DS firmware dump") == 0)
	{
		firm firm;
		firm.load_header(li);
		firm.load_file(li);
	} else {
		_3ds _3ds;
		_3ds.load_header(li);
		_3ds.load_file(li);
	}
}


loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
	0,                            // loader flags
	accept_file,
	load_file,
	NULL,
	NULL,
	NULL
};