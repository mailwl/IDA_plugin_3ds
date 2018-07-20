#include <vector>
#include "ctr.h"
#include "idaldr.h"

#pragma comment(lib, "ida")

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

struct ExHeader_SystemInfoFlags {
    u8 reserved[5];
    u8 flag;
    u8 remaster_version[2];
};

struct ExHeader_CodeSegmentInfo {
    u32 address;
    u32 num_max_pages;
    u32 code_size;
};

struct ExHeader_CodeSetInfo {
    u8 name[8];
    ExHeader_SystemInfoFlags flags;
    ExHeader_CodeSegmentInfo text;
    u32 stack_size;
    ExHeader_CodeSegmentInfo ro;
    u8 reserved[4];
    ExHeader_CodeSegmentInfo data;
    u32 bss_size;
};

struct ExHeader_DependencyList {
    u8 program_id[0x30][8];
};

struct ExHeader_SystemInfo {
    u64 save_data_size;
    u8 jump_id[8];
    u8 reserved_2[0x30];
};

struct ExHeader_StorageInfo {
    u8 ext_save_data_id[8];
    u8 system_save_data_id[8];
    u8 reserved[8];
    u8 access_info[7];
    u8 other_attributes;
};

struct ExHeader_ARM11_SystemLocalCaps {
    u64 program_id;
    u32 core_version;
    u8 reserved_flags[2];
    u8 flags;
    u8 priority;
    u8 resource_limit_descriptor[0x10][2];
    ExHeader_StorageInfo storage_info;
    u8 service_access_control[0x20][8];
    u8 ex_service_access_control[0x2][8];
    u8 reserved[0xf];
    u8 resource_limit_category;
};

struct ExHeader_ARM11_KernelCaps {
    u32 descriptors[28];
    u8 reserved[0x10];
};

struct ExHeader_ARM9_AccessControl {
    u8 descriptors[15];
    u8 descversion;
};

struct ExHeader_Header {
    ExHeader_CodeSetInfo codeset_info;
    ExHeader_DependencyList dependency_list;
    ExHeader_SystemInfo system_info;
    ExHeader_ARM11_SystemLocalCaps arm11_system_local_caps;
    ExHeader_ARM11_KernelCaps arm11_kernel_caps;
    ExHeader_ARM9_AccessControl arm9_access_control;
    struct {
        u8 signature[0x100];
        u8 ncch_public_key_modulus[0x100];
        ExHeader_ARM11_SystemLocalCaps arm11_system_local_caps;
        ExHeader_ARM11_KernelCaps arm11_kernel_caps;
        ExHeader_ARM9_AccessControl arm9_access_control;
    } access_desc;
};

struct fw_sect_header_t {
    u32 offset;
    u32 address;
    u32 size;
    u32 fw_type; // 0 - arm9, 1 = arm11
    char sha256[0x20];
};

struct firm_header_t {
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
static bool LZSS_Decompress(const u8* compressed, u32 compressed_size, u8* decompressed,
                            u32 decompressed_size) {
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

class firm {
public:
    bool load_header(linput_t*);
    void load_file(linput_t*);

private:
    firm_header_t fw;
};

bool firm::load_header(linput_t* li) {
    u32 size = qlsize(li);
    if (size < sizeof(firm_header_t))
        return false;
    qlseek(li, 0);
    qlread(li, &fw, sizeof(firm_header_t));
    if (MakeMagic('F', 'I', 'R', 'M') != fw.magic)
        return false;
    return true;
}

void firm::load_file(linput_t* li) {
    for (int i = 0; i < 4; ++i) {
        const fw_sect_header_t& section = fw.sections[i];
        if (section.offset == 0 && section.size == 0)
            continue;
        qlseek(li, section.offset);

        set_selector(i + 1, 0);
        if (i == 0) {
            add_segm(i + 1, section.address, section.address + section.size, NAME_DATA, CLASS_DATA);
        } else {
            char name[0x20];
            qsnprintf(name, 0x20, ".text%d", i + 1);
            add_segm(i + 1, section.address, section.address + section.size, name, CLASS_CODE);
        }

        set_segm_addressing(getseg(section.address), 1); // enable 32bit addressing
        file2base(li, section.offset, section.address, section.address + section.size, 0);
    }
}

class _3ds {
public:
    _3ds() : ncch_offset(0) {}
    bool load_header(linput_t*);
    void load_file(linput_t*);

private:
    NCCH_Header ncch_header;
    u32 ncch_offset;
    /*exheader_t*/
    ExHeader_Header exheader_header;
    ExeFs_Header exefs_header;
    bool is_encrypted = false;
    ctr_aes_context aes{};
    ctr_rsa_context rsa{};
    u8 key[16];
    u8 exheadercounter[16];
    u8 exefscounter[16];
};

bool _3ds::load_header(linput_t* li) {
    u32 size = qlsize(li);
    if (size < 0x4000)
        return false;
    qlseek(li, 0);
    qlread(li, &ncch_header, sizeof(ncch_header));

    if (MakeMagic('N', 'C', 'S', 'D') == ncch_header.magic) {
        ncch_offset = 0x4000;
        qlseek(li, ncch_offset);
        qlread(li, &ncch_header, sizeof(ncch_header));
    }
    if (MakeMagic('N', 'C', 'C', 'H') != ncch_header.magic)
        return false;
    return true;
}

void _3ds::load_file(linput_t* li) {
    qlread(li, &exheader_header, sizeof(exheader_header));

    // Check if ExHeader encrypted
    if (memcmp(&exheader_header.arm11_system_local_caps.program_id, &ncch_header.program_id, 8)) {
        // Fixed Crypto Key
        if (ncch_header.flags[7] & 0x1) {
            is_encrypted = true;
            memset(&exheadercounter, 0, sizeof(exheadercounter));
            memset(&exefscounter, 0, sizeof(exefscounter));
            if (ncch_header.version == 2 || ncch_header.version == 0) {
                for (u8 i = 0; i < 8; i++) {
                    exefscounter[i] = exheadercounter[i] = ncch_header.partition_id[7 - i];
                }
                exheadercounter[8] = 1;
                exefscounter[8] = 2;
            }
        }
    }

    if (is_encrypted) {
        memset(&key, 0, sizeof(key));
        ctr_init_counter(&aes, key, exheadercounter);
        ctr_crypt_counter(&aes, (u8*)&exheader_header, (u8*)&exheader_header,
                          sizeof(ExHeader_Header));
    }

    bool is_compressed = (exheader_header.codeset_info.flags.flag & 1) == 1;

    u32 exefs_offset = ncch_header.exefs_offset * kBlockSize;

    qlseek(li, exefs_offset + ncch_offset);

    qlread(li, &exefs_header, sizeof(exefs_header));

    if (is_encrypted) {
        memset(&key, 0, sizeof(key));
        ctr_init_counter(&aes, key, exefscounter);
        ctr_crypt_counter(&aes, (u8*)&exefs_header, (u8*)&exefs_header, sizeof(ExeFs_Header));
    }

    std::vector<u8> code;

    for (u32 i = 0; i < 8; ++i) {
        const ExeFs_SectionHeader& section = exefs_header.section[i];
        if (0 == qstrcmp(section.name, ".code")) {
            u32 offset = section.offset + exefs_offset + sizeof(ExeFs_Header) + ncch_offset;
            qlseek(li, offset);
            if (is_compressed) {
                std::vector<u8> temp;
                temp.resize(section.size);
                qlread(li, &temp[0], section.size);
                if (is_encrypted) {
                    memset(&key, 0, sizeof(key));
                    ctr_init_counter(&aes, key, exefscounter);
                    ctr_add_counter(&aes, (section.offset + sizeof(ExeFs_Header)) / 0x10);
                    ctr_crypt_counter(&aes, (u8*)&temp[0], (u8*)&temp[0], section.size);
                }
                u32 decompressed_size = LZSS_GetDecompressedSize(&temp[0], section.size);
                code.resize(decompressed_size);
                bool rc = LZSS_Decompress(&temp[0], section.size, &code[0], decompressed_size);
                if (!rc)
                    qexit(1);
            } else {
                code.resize(section.size);
                qlread(li, &code[0], section.size);
                if (is_encrypted) {
                    memset(&key, 0, sizeof(key));
                    ctr_init_counter(&aes, key, exefscounter);
                    ctr_add_counter(&aes, (section.offset + sizeof(ExeFs_Header)) / 0x10);
                    ctr_crypt_counter(&aes, (u8*)&code[0], (u8*)&code[0], section.size);
                }
            }
            break;
        }
    }

    bool aligned =
        code.size() >= (exheader_header.codeset_info.text.code_size + exheader_header.codeset_info.ro.code_size +
                        exheader_header.codeset_info.data.code_size);
    u32 offset = 0;

    set_selector(1, 0);
    if (!add_segm(1, exheader_header.codeset_info.text.address,
                  exheader_header.codeset_info.text.address + exheader_header.codeset_info.text.num_max_pages * 0x1000,
                  NAME_CODE, CLASS_CODE))
        qexit(1);
    set_segm_addressing(getseg(exheader_header.codeset_info.text.address), 1); // enable 32bit addressing
    mem2base(&code[offset], exheader_header.codeset_info.text.address,
             exheader_header.codeset_info.text.address + exheader_header.codeset_info.text.code_size, -1);

    offset =
        aligned ? exheader_header.codeset_info.text.num_max_pages * 0x1000 : exheader_header.codeset_info.text.code_size;

    set_selector(2, 0);
    if (!add_segm(2, exheader_header.codeset_info.ro.address,
                  exheader_header.codeset_info.ro.address + exheader_header.codeset_info.ro.num_max_pages * 0x1000, ".ro",
                  CLASS_CONST))
        qexit(1);
    mem2base(&code[offset], exheader_header.codeset_info.ro.address,
             exheader_header.codeset_info.ro.address + exheader_header.codeset_info.ro.code_size, -1);

    set_selector(3, 0);
    if (!add_segm(3, exheader_header.codeset_info.data.address,
                  exheader_header.codeset_info.data.address + exheader_header.codeset_info.data.num_max_pages * 0x1000,
                  NAME_DATA, CLASS_DATA))
        qexit(1);

    offset =
        aligned ? (exheader_header.codeset_info.text.num_max_pages + exheader_header.codeset_info.ro.num_max_pages) * 0x1000
                : exheader_header.codeset_info.text.code_size + exheader_header.codeset_info.ro.code_size;

    mem2base(&code[offset], exheader_header.codeset_info.data.address,
             exheader_header.codeset_info.data.address + exheader_header.codeset_info.data.code_size, -1);

    set_selector(4, 0);
    add_segm(4, (exheader_header.codeset_info.data.address + exheader_header.codeset_info.data.num_max_pages * 0x1000),
             (exheader_header.codeset_info.data.address + exheader_header.codeset_info.data.num_max_pages * 0x1000) +
                 exheader_header.codeset_info.bss_size,
             NAME_BSS, CLASS_BSS);
}

class cia {};

int idaapi accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename) {

    firm firm;
    if (firm.load_header(li)) {
		*fileformatname = "Nintendo 3DS firmware dump";
		*processor = "arm";
        return 1 | ACCEPT_FIRST;
    }

    _3ds _3ds;
    if (_3ds.load_header(li)) {
		*fileformatname = "Nintendo 3DS game dump";
		*processor = "arm";
        return 1 | ACCEPT_FIRST;
    }
    return 0;
}

void idaapi load_file(linput_t* li, ushort neflags, const char* fileformatname) {
	set_processor_type("ARM", SETPROC_LOADER); //ida complains otherwise and putting this in accept_file won't work
    if (qstrcmp(fileformatname, "Nintendo 3DS firmware dump") == 0) {
        firm firm;
        firm.load_header(li);
        firm.load_file(li);
    } else {
        _3ds _3ds;
        _3ds.load_header(li);
        _3ds.load_file(li);
    }
}

loader_t LDSC = {IDP_INTERFACE_VERSION,
                 0, // loader flags
                 accept_file,
                 load_file,
                 NULL,
                 NULL,
                 NULL};
