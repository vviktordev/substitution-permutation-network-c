#include <stdio.h>
#include <stdint.h>
#include "sha256.h"

#define _FILE_OFFSET_BITS 64
#define NUMBER_OF_ROUNDS 4
#define BLOCK_SIZE 2                   // block size in bytes
#define NUMBER_OF_SBOXES 4
#define BITS_IN_BYTE 8

typedef struct {
    int current_round;
    unsigned long long current_block;
    char mode;

    uint8_t* round_keys[NUMBER_OF_ROUNDS];
    uint8_t data[1024];

    FILE* output_fp;
    unsigned long long fp_pos;
    size_t bytes_read;
    char* target_output_file_path;
    char* temp_output_file_path;

    uint8_t* sbox_map;
    uint8_t* pbox_map;

} SPN_Context;

typedef enum {
    SPN_SUCCESS = 0,
    SPN_ERROR_FILE_READ,
    SPN_ERROR_FILE_WRITE,
    SPN_ERROR_FILE_OPEN,
    SPN_ERROR_FILE_REMOVE,
    SPN_ERROR_MEMORY,
    SPN_ERROR_INVALID_ARGS,
    SPN_ERROR_INVALID_MODE,
} spn_error_t;

spn_error_t spn_init(SPN_Context* ctx, char* mode, char* input_file_path, char* output_file_path, char* password);
spn_error_t spn_sbox(SPN_Context* ctx);
spn_error_t spn_pbox(SPN_Context* ctx);
spn_error_t spn_data_key_XOR(SPN_Context* ctx);
spn_error_t spn_update_file(SPN_Context* ctx);
spn_error_t spn_final(SPN_Context* ctx);
void spn_cleanup(SPN_Context* ctx);
