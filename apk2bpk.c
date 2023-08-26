#ifdef __MINGW32__ // Fix slow printf on mingw
#define __USE_MINGW_ANSI_STDIO 0
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#ifndef _WIN32
#include <sys/mman.h>
#else
#include "mman.h"
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef PATH_MAX
#if defined(_WIN32) || defined(__CYGWIN__)
#define PATH_MAX 256
#elif defined(__linux__)
#define PATH_MAX 4096
#else
#define PATH_MAX 1024
#endif
#endif // PATH_MAX

#define pk2bpk(pk) (((pk%0x1000000)<<8)+0x42)
#define bpk2pk(bpk) (((bpk>>24)+1)<<24)+(bpk>>8)

const uint8_t *xorCodeEOCD = (uint8_t *)"END_OF_CENTRAL_DIRECTORY_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeCD = (uint8_t *)"CENTRAL_DIRECTORY_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeLOCAL = (uint8_t *)"LOCAL_FILE_HEADER_XOR_CODE_OF_BBK_APK_ENCRYPTION";


#define local_file_magic 0x04034b50 // general zip header magic
#define bbk_local_file_magic pk2bpk(local_file_magic) // bbk smart ass magic
#pragma pack(push, 1)
struct local_file_header {
    uint32_t magic;
    uint16_t version;
    uint16_t flag;
    uint16_t method;
    uint16_t last_modified_time;
    uint16_t last_modified_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
};
#pragma pack(pop)

#define data_descriptor_magic 0x08074b50
#define bbk_data_descriptor_magic pk2bpk(data_descriptor_magic) // bbk smart ass data descriptor magic

#pragma pack(push, 1)
struct data_descriptor {
    uint32_t magic;
    // For easy way to encode ...
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    // Use below to encode
    //uint8_t data[sizeof(uint32_t)*3];
};
#pragma pack(pop)

#define central_directory_file_header_magic 0x02014b50
#define bbk_central_directory_file_header_magic pk2bpk(central_directory_file_header_magic) // bbk smart ass end

#pragma pack(push, 1)
struct directory_source { // 0x02014b50
    uint32_t magic;
    uint16_t cver;
    uint16_t dver;
    uint16_t flag;
    uint16_t compress_method;
    uint16_t last_modified_time;
    uint16_t last_modifiled_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_length;
    uint16_t annotation_length;
    uint16_t subsection;
    uint16_t attrib_inside;
    uint32_t attrib_outside;
    uint32_t offset;
    //uint8_t *filename[0];
    //uint8_t *extra[0];
    //uint8_t *annotation[0];
};
#pragma pack(pop)

#define end_of_central_magic 0x06054b50
#define bbk_end_of_central_magic pk2bpk(end_of_central_magic)

#pragma pack(push, 1)
struct end_of_central_directory { //END_OF_CENTRAL_DIRECTORY
    uint32_t magic;
    uint16_t disk_num;
    uint16_t central_start_offset_disk_num;
    uint16_t record_central_num;
    uint16_t total_central_directory_num;
    uint32_t central_size;
    uint32_t central_start_offset;
    uint16_t extra_length;
    //uint8_t data[18];
};
#pragma pack(pop)

// https://source.android.com/docs/security/features/apksigning/v2?hl=zh-cn#apk-signing-block
struct apk_signature_v2 {
    uint64_t size;
    uint8_t *data;
};

enum {
    CFG_ENCODE,
    CFG_DECODE,
};

static struct config {
    int verbose;
    int mode; // 0 encode, 1 decode
    char *input;
    char *output;
} cfg;

static int xor(uint8_t* val, uint32_t size, const uint8_t *xorCode) {
    if (size == 0)
        return -1;
    int xlen = strlen((const char*)xorCode);
    for (uint32_t i=0;i<size;i++)
        val[i] = xorCode[(i)%xlen] ^ val[i];
    return 0;
}
#ifdef _WIN32
static ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return write(fd, buf, count);
}
#endif
static inline off_t get_eocd_offset(uint8_t *mem, off_t size) {
    uint32_t magic;
    int flag = 0;
    while(1) {
        if (size == 0) break;
        if (mem[size] == (uint8_t)(end_of_central_magic%0x100) ||
            mem[size] == (uint8_t)(bbk_end_of_central_magic%0x100)) {
            memcpy(&magic, mem + size, sizeof(magic));
            if (magic == end_of_central_magic || 
                magic == bbk_end_of_central_magic) {
                    flag = 1;
                    break;
            }
        }
        size--;
    }
    if (flag)
        return size;
    else return 0;
}

static inline void parse_magic(uint32_t *magic) {
    *magic = (cfg.mode == CFG_ENCODE) ? pk2bpk(*magic) : bpk2pk(*magic);
}

static int parse_zip(char* input, char* output, int mode, int verbose) {
    int ret = 0;
    int fdi, fdo;
    struct local_file_header hl;
    struct data_descriptor hdd;
    struct end_of_central_directory heo;
    struct directory_source hds;
    struct apk_signature_v2 sig;
    off_t offset = 0, local_offset = 0, sig_offset = 0;
    uint8_t *buf;

if (access(output, F_OK)==0) {
        ret = remove(output);
        if (ret) {
            printf("Error: Cannot remove file %s\n", output);
        }
    }

    fdi = open(input, O_RDONLY | O_BINARY);
    fdo = open(output, O_CREAT | O_EXCL | O_TRUNC | O_RDWR | O_BINARY);
    if (!fdo) {
        printf("Error: Faild to creat new file.");
        return EIO;
    }

    // Check file is apk or bpk
    lseek(fdi, 0, 0);
    read(fdi, &hl, 28);

    if ((hl.magic != local_file_magic) && (hl.magic != bbk_local_file_magic)) {
        fprintf(stderr, "File does not seems like a apk or bpk file.\n");
        close(fdi); close(fdo);
        return 1;
    }
    if (hl.magic == bbk_local_file_magic && mode != CFG_DECODE) {
        fprintf(stderr, "File seems already encrypted.\n");
        close(fdi);
        return 1;
    }

    printf("Converting [%s] -> [%s] ... \n", input, output);

    // Get file size
    struct stat st;
    stat(input, &st);
    //fsize = st.st_size;

    // use mmap get magic
    uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fdi, 0);
    uint8_t *ptr;
    uint32_t data_len;
    uint16_t flag;
    //uint32_t central_directory_offset;
    
    // parse
    // Get end struct
    offset = get_eocd_offset(mem, st.st_size);
    if (verbose) {
        printf("Find EOCD at              :\t%ld\n", offset);
    }
    if (offset == 0) {
        printf("Error: Cannot find eocd magic %08x at end\n", (mode == CFG_ENCODE ? end_of_central_magic : bbk_end_of_central_magic));
        return EBADF;
    }
    ptr = mem + offset;
    memcpy(&heo, ptr, sizeof(heo));
    parse_magic(&heo.magic);
    xor((uint8_t*)&heo+sizeof(heo.magic), sizeof(heo)-sizeof(heo.magic), xorCodeEOCD);
    pwrite(fdo, &heo, sizeof(heo), offset);
    if (mode == CFG_ENCODE) {
        // convert back cause below code cannot detect correctly
        xor((uint8_t*)&heo+sizeof(heo.magic), sizeof(heo)-sizeof(heo.magic), xorCodeEOCD);
    }
    // write eocd extra
    if (heo.extra_length != 0U) {
        if (verbose) {
            printf("Find End Extra at         :\t%ld\n", offset+sizeof(heo));
        }
        ptr = mem + offset + sizeof(heo);
        pwrite(fdo, ptr, heo.extra_length, offset+sizeof(heo));
    }
    if (heo.extra_length != 0U) {
        ptr += sizeof(heo);
        write(fdo, ptr, heo.extra_length);
    }
    if (verbose) {
        printf("Find Central Direcotry Num: \t%u\n"
               "Find Central Total size   : \t%u\n"
               "Find Central Offset at dec: \t%u | hex %08x\n",
                    heo.total_central_directory_num, heo.central_size, heo.central_start_offset, heo.central_start_offset);
    }
    
    // parse central directory
    offset = heo.central_start_offset;
    for (uint16_t i=1;i<=heo.total_central_directory_num;i++) {
        //printf("Parse central directory offset at: %ld \t| %08x\n", offset, (uint32_t)offset);
        if (verbose) {
            printf("[ %06u / %06u ] Parsing ... \r", i, heo.total_central_directory_num);
            fflush(stdout);
            if (i == heo.total_central_directory_num) {
                printf("[ %06u / %06u ] Parsing ... Done!\n", i, heo.total_central_directory_num);
            }
        }

        ptr = mem + offset;
        memcpy(&hds, ptr, sizeof(hds));
        if (mode == CFG_DECODE) {
            xor((uint8_t*)&hds+sizeof(hds.magic), sizeof(hds)-sizeof(hds.magic), xorCodeCD);
        }
        flag = hds.flag;
        data_len = sizeof(hds) - sizeof(hds.magic) + hds.extra_length + hds.annotation_length + hds.file_name_length;
        lseek(fdo, offset, SEEK_SET);
        // parse magic
        parse_magic(&hds.magic);
        
        write(fdo, &hds.magic, sizeof(hds.magic));
        offset += sizeof(hds.magic);
        // parse data, file name and extra
        buf = (uint8_t*)malloc(data_len);
        ptr += sizeof(hds);
        
        memcpy(buf, (uint8_t*)&hds + sizeof(hds.magic), sizeof(hds) - sizeof(hds.magic));
        memcpy(buf + sizeof(hds) - sizeof(hds.magic), ptr, hds.extra_length + hds.annotation_length + hds.file_name_length);
        if (mode == CFG_ENCODE) {
            xor(buf, data_len, xorCodeCD);
        } else {
            xor(buf, sizeof(hds)-sizeof(hds.magic), xorCodeCD);
            xor(buf, data_len, xorCodeCD);
        }

        write(fdo, buf, data_len);
        
        free(buf);
        offset += data_len;
        

        // parse local file
        local_offset = hds.offset;
        // get signature offset
        sig_offset = local_offset + sizeof(hl) + hds.file_name_length + hl.extra_field_length + hds.compressed_size;
        if (flag&0x8) {
            sig_offset += sizeof(hdd);
        }
        ptr = mem + local_offset;
        memcpy(&hl, ptr, sizeof(hl));

        if (mode == CFG_DECODE) {
            xor((uint8_t*)&hl+sizeof(hl.magic), sizeof(hl)-sizeof(hl.magic)-sizeof(hl.extra_field_length), xorCodeLOCAL);
        }

        lseek(fdo, offset, SEEK_SET);
        parse_magic(&hl.magic);
        // write data
        pwrite(fdo, ptr + sizeof(hl)+ hds.file_name_length + hds.extra_length, hds.compressed_size + hl.extra_field_length, local_offset+sizeof(hl)+hds.file_name_length+hds.extra_length);

        buf = (uint8_t*)malloc(hds.file_name_length);
        memcpy(buf, ptr+sizeof(hl), hds.file_name_length);
        
        xor(buf, hds.file_name_length, xorCodeLOCAL);
        // write file name
        pwrite(fdo, buf, hds.file_name_length, local_offset+sizeof(hl));
        free(buf);
        
        // write extra
        pwrite(fdo, ptr+sizeof(hl)+hds.file_name_length, hds.extra_length, local_offset+sizeof(hl)+hds.file_name_length);
        if ((flag & 0x8)) { // 50 4b 07 08
            memcpy(&hdd, ptr+sizeof(hl)+hds.file_name_length+hds.extra_length+hds.compressed_size, sizeof(hdd));
            xor((uint8_t*)&hdd+sizeof(hdd.magic), sizeof(hdd)-sizeof(hdd.magic), xorCodeLOCAL); // new use LOCAL old use CD
            parse_magic(&hdd.magic);
            pwrite(fdo, &hdd, sizeof(hdd), local_offset+sizeof(hl)+hds.file_name_length+hds.extra_length+hds.compressed_size);
        }

        if (mode == CFG_ENCODE) {
            xor((uint8_t*)&hl+sizeof(hl.magic), sizeof(hl)-sizeof(hl.magic)-sizeof(hds.extra_length), xorCodeLOCAL);
        }

        if (!(flag & 0x8)) { // 0xFFFFFFFF
            hl.crc32 = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.crc32;
            hl.compressed_size = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.compressed_size;
            hl.uncompressed_size = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.uncompressed_size;
        } else {
            hl.crc32 = (mode == CFG_ENCODE) ? 0U : hds.crc32;
            hl.compressed_size = (mode == CFG_ENCODE) ? 0U : hds.compressed_size;
            hl.uncompressed_size = (mode == CFG_ENCODE) ? 0U : hds.uncompressed_size;
        }
        pwrite(fdo, &hl, sizeof(hl), local_offset);
        
    }
    
    // cpoy sig
    // from sig_offset -- heo.
    if (!sig_offset){
        printf("Error: This should not happen.\n\tSig offset has not found.\n");
        return EIO;
    }
    while(mem[sig_offset]==0U) { // skip zero
        sig_offset++;
    }
    if (sig_offset < heo.central_start_offset) {
        ptr = mem + sig_offset;
        memcpy(&sig.size, ptr, sizeof(sig.size));
        if (verbose) {
            printf("Find apk signature at     :\t%ld\n"
                   "Find apk signature Size   :\t%lu\n", sig_offset, sig.size);
        }
        pwrite(fdo, ptr, sizeof(sig.size)+sig.size, sig_offset);
    } else {
        printf("Warning: This apk file have no signature.\n"
               "\tSkip write signature.\n");
    }
    // release
    munmap(mem, st.st_size);
    close(fdi); close(fdo);
    chmod(output, 0755);
    printf("Done!\n");
    return ret;
}

static void usage() {
    printf(
        "apk2bpk -i [file] -o [file] -d\n"
        "Usage: \n"
        "\t-i [file]\tFile input\n"
        "\t-o [file]\tFile output\n"
        "\t-d       \tDecode mode\n"
        "\t-v       \tVerbose\n"
        "\t-h       \tPrint This usage message\n"
        "This program convert apk -> bpk or convert back.\n"
        "Main program from azwhikaru@github.com\n"
        "C program from affggh@github.com\n"
    );
}

static void parse_arg(int argc, char** argv) {
    int opt;
    const char *optstr = "i:o:dvh";
    cfg.mode = CFG_ENCODE; // init
    cfg.verbose = 0;
    while((opt = getopt(argc, argv, optstr)) != -1) {
        switch(opt) {
            case 'i':
                cfg.input = strdup(optarg);
                break;
            case 'o':
                cfg.output = strdup(optarg);
                break;
            case 'd':
                cfg.mode = CFG_DECODE; // decode
                break;
            case 'v':
                cfg.verbose = 1;
                break;
            case 'h':
                usage(); exit(0);
                break;
            default:
                break;
        }
    }
}

int main(int argc, char** argv) {
    char output[PATH_MAX];
    int ret = 0;
    if (argc<2) {
        usage(); return 1;
    }
    parse_arg(argc, argv);
    if (cfg.input == NULL) {
        fprintf(stderr, "Error: Input file not defined.\n");
        return 1;
    }
    if (access(cfg.input, F_OK) != 0) {
        fprintf(stderr, "Error: File input [%s] does not exist.\n", cfg.input);
        return EEXIST;
    }
    if (cfg.output == NULL) {
        sprintf(output, "%s%s", cfg.input, (cfg.mode == CFG_ENCODE) ? ".bpk" : ".apk");
        cfg.output = output;
    }
    if (access(cfg.output, F_OK) == 0) {
        ret = unlink(cfg.output);
        if (ret) {
            printf("Error: Cannot remove exist output file.\n");
            return EIO;
        }
    }
    ret = parse_zip(cfg.input, cfg.output, cfg.mode, cfg.verbose);
    return ret;
}
