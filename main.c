#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "main.h"

int main(int argc, char* argv[]) {
    spn_error_t err;
    SPN_Context spn_ctx;

    if (argc != 5) {
        fprintf(stderr, "Error: Wrong amount of arguments. Expected 4 - mode(e or d) input_path output_path key\n");
        return SPN_ERROR_INVALID_ARGS;
    }

    if (argv[1][0] != 'e' && argv[1][0] != 'd') {
        fprintf(stderr, "Error: Wrong execution mode (first argument). Expected e for encryption or d for decryption\n");
        return SPN_ERROR_INVALID_MODE;
    }

    err = spn_init(&spn_ctx, argv[1], argv[2], argv[3], argv[4]);
    if (err != SPN_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize SPN context (code: %d)\n", err);
        spn_cleanup(&spn_ctx);
        return err;
    }

    for ( ; spn_ctx.current_round < NUMBER_OF_ROUNDS; spn_ctx.current_round++) {
        while ((spn_ctx.bytes_read = fread(spn_ctx.data, 1, sizeof(spn_ctx.data), spn_ctx.output_fp)) > 0) {
            spn_ctx.fp_pos += spn_ctx.bytes_read;

            for (spn_ctx.current_block = 0; spn_ctx.current_block < (spn_ctx.bytes_read / BLOCK_SIZE); spn_ctx.current_block++) {
                if (spn_ctx.mode == 'e') {
                    spn_sbox(&spn_ctx);
                    spn_pbox(&spn_ctx);
                    spn_data_key_XOR(&spn_ctx);
                } else {
                    spn_data_key_XOR(&spn_ctx);
                    spn_pbox(&spn_ctx);
                    spn_sbox(&spn_ctx);
                }
            }

            err = spn_update_file(&spn_ctx);
            if (err != SPN_SUCCESS) {
                fprintf(stderr, "Error updating file (code: %d)\n", err);
                spn_cleanup(&spn_ctx);
                return err;
            }
        }

        if (ferror(spn_ctx.output_fp)) {
            fprintf(stderr, "Error reading file\n");
            spn_cleanup(&spn_ctx);
            return SPN_ERROR_FILE_READ;
        }

        if (fseek(spn_ctx.output_fp, 0, SEEK_SET) != 0) {
            fprintf(stderr, "Error seeking file\n");
            spn_cleanup(&spn_ctx);
            return SPN_ERROR_FILE_READ;
        }
        spn_ctx.fp_pos = 0;
    }

    err = spn_final(&spn_ctx);
    if (err != SPN_SUCCESS) {
        fprintf(stderr, "Error during finalization (code: %d)\n", err);
        spn_cleanup(&spn_ctx);
        return err;
    }
    spn_cleanup(&spn_ctx);

    return 0;
}

spn_error_t spn_init(SPN_Context* ctx, char* mode, char* input_file_path, char* output_file_path, char* password) {
    SHA256_CTX sha256_ctx;
    BYTE sha256_key[SHA256_BLOCK_SIZE];
    size_t password_len = 0;
    BYTE* byte_password;
    uint8_t* round_key;

    uint8_t sbox_map_encryption_temp[16] = {
        14, 4, 13, 1, 2, 15, 11, 8,
        3, 10, 6, 12, 5, 9, 0, 7
    };
    uint8_t sbox_map_decryption_temp[16] = {
        14, 3, 4, 8, 1, 12, 10, 15,
        7, 13, 9, 6, 11, 2, 0, 5
    };
    uint8_t* sbox_map;

    uint8_t pbox_map_temp[16] = {
        0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15
    };
    uint8_t* pbox_map;

    FILE* input_file;
    FILE* output_file;
    char* temp_output_file_path;
    unsigned long long input_file_size = 0;
    size_t bytes_read = 0;
    uint8_t buffer[1024] = {0};
    uint8_t bytes_to_pad = 0;

    ctx->target_output_file_path = output_file_path;
    ctx->mode = mode[0];

    password_len = strlen(password);
    byte_password = malloc(password_len);
    if (byte_password == NULL) {
        return SPN_ERROR_MEMORY;
    }

    // sha256_update expects an array of BYTEs (unsigned chars), not chars
    for (size_t i = 0; i < password_len; i++) {
        byte_password[i] = (BYTE)password[i];
    }

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, byte_password, password_len);
    sha256_final(&sha256_ctx, sha256_key);
    free(byte_password);

    // generate round keys from the master key by splitting it
    for (int i = 0; i < NUMBER_OF_ROUNDS; i++) {
        round_key = malloc(BLOCK_SIZE);
        if (round_key == NULL) {
            return SPN_ERROR_MEMORY;
        }

        for (int j = 0; j < BLOCK_SIZE; j++) {
            round_key[j] = sha256_key[i * BLOCK_SIZE + j];
        }

        if (ctx->mode == 'e') {
            ctx->round_keys[i] = round_key;
        } else {
            ctx->round_keys[NUMBER_OF_ROUNDS - i - 1] = round_key;
        }
    }

    sbox_map = malloc(16);
    if (sbox_map == NULL) {
        return SPN_ERROR_MEMORY;
    }
    ctx->sbox_map = sbox_map;

    for (int i = 0; i < 16; i++) {
        if (ctx->mode == 'e') {
            sbox_map[i] = sbox_map_encryption_temp[i];
        } else {
            sbox_map[i] = sbox_map_decryption_temp[i];
        }
    }

    pbox_map = malloc(16);
    if (pbox_map == NULL) {
        return SPN_ERROR_MEMORY;
    }
    ctx->pbox_map = pbox_map;

    for (int i = 0; i < 16; i++) {
        pbox_map[i] = pbox_map_temp[i];
    }

    input_file = fopen(input_file_path, "rb");
    if (input_file == NULL) {
        return SPN_ERROR_FILE_OPEN;
    }

    temp_output_file_path = malloc(strlen(output_file_path) + 5);
    if (temp_output_file_path == NULL) {
        return SPN_ERROR_MEMORY;
    }
    ctx->temp_output_file_path = temp_output_file_path;
    strcpy(temp_output_file_path, output_file_path);

    output_file = fopen(strcat(temp_output_file_path, ".tmp"), "w+b");
    ctx->output_fp = output_file;
    if (output_file == NULL) {
        return SPN_ERROR_FILE_OPEN;
    }

    // copy the input file to the output file
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
        input_file_size += bytes_read;
        if (fwrite(buffer, bytes_read, 1, output_file) != 1) {
            return SPN_ERROR_FILE_WRITE;
        }
        if (fflush(output_file) == EOF) {
            return SPN_ERROR_FILE_WRITE;
        }
    }

    if (ferror(input_file)) {
        return SPN_ERROR_FILE_READ;
    }
    fclose(input_file);

    // padding as per PKCS #7 specification
    if (ctx->mode == 'e') {
        bytes_to_pad = input_file_size % BLOCK_SIZE == 0 ? BLOCK_SIZE : input_file_size % BLOCK_SIZE;
        for (int i = 0; i < bytes_to_pad; i++) {
            if (fputc(bytes_to_pad, output_file) == EOF) {
                return SPN_ERROR_FILE_WRITE;
            }
        }
        if (fflush(output_file) == EOF) {
            return SPN_ERROR_FILE_WRITE;
        }
    }
    if (fseek(output_file, 0, SEEK_SET) != 0) {
        return SPN_ERROR_FILE_READ;
    }

    ctx->current_round = 0;
    ctx->current_block = 0;
    ctx->fp_pos = 0;
    ctx->bytes_read = 0;

    return SPN_SUCCESS;
}

spn_error_t spn_sbox(SPN_Context* ctx) {
    uint8_t sbox_values[NUMBER_OF_SBOXES] = {0};
    uint8_t first_byte = ctx->data[ctx->current_block * BLOCK_SIZE];
    uint8_t second_byte = ctx->data[ctx->current_block * BLOCK_SIZE + 1];

    // the sbox operates on 4 bits at a time, but a byte is the smallest data type
    sbox_values[0] = first_byte >> 4;          // shift 4 MSBs into LSBs
    sbox_values[1] = first_byte & 0x0f;        // keep only 4 LSBs
    sbox_values[2] = second_byte >> 4;
    sbox_values[3] = second_byte & 0x0f;

    for (int i = 0; i < NUMBER_OF_SBOXES; i++) {
        sbox_values[i] = ctx->sbox_map[sbox_values[i]];
    }

    ctx->data[ctx->current_block * BLOCK_SIZE] = (sbox_values[0] << 4) | sbox_values[1];
    ctx->data[ctx->current_block * BLOCK_SIZE + 1] = (sbox_values[2] << 4) | sbox_values[3];

    return SPN_SUCCESS;
}

spn_error_t spn_pbox(SPN_Context* ctx) {
    int byte_num = 0;
    int bit_num = 0;
    int new_byte_num = 0;
    int new_bit_num = 0;
    uint8_t bit = 0;
    uint8_t pbox_inputs[BLOCK_SIZE] = {0};
    uint8_t new_block[BLOCK_SIZE] = {0};

    pbox_inputs[0] = ctx->data[ctx->current_block * BLOCK_SIZE];
    pbox_inputs[1] = ctx->data[ctx->current_block * BLOCK_SIZE + 1];

    for (int i = 0; i < BLOCK_SIZE * BITS_IN_BYTE; i++) {
        byte_num = i / BITS_IN_BYTE;                                // the number of the byte we are currently permutating
        bit_num = i % BITS_IN_BYTE;                                 // the number of the bit in the byte we are currently permutating

        new_byte_num = ctx->pbox_map[i] / BITS_IN_BYTE;             // the number of the byte the bit is going to be moved into
        new_bit_num = ctx->pbox_map[i] % BITS_IN_BYTE;              // the position of the bit inside the new byte

        bit = pbox_inputs[byte_num] & (0x80 >> bit_num);            // separate the bit we are permutating

        if (bit_num < new_bit_num) {
            bit = bit >> (new_bit_num - bit_num);
        } else {
            bit = bit << (bit_num - new_bit_num);
        }

        new_block[new_byte_num] |= bit;
    }

    for (int i = 0; i < BLOCK_SIZE; i++) {
        ctx->data[ctx->current_block * BLOCK_SIZE + i] = new_block[i];
    }

    return SPN_SUCCESS;
}

spn_error_t spn_data_key_XOR(SPN_Context* ctx) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        ctx->data[ctx->current_block * BLOCK_SIZE + i] ^= ctx->round_keys[ctx->current_round][i];
    }

    return SPN_SUCCESS;
}

spn_error_t spn_update_file(SPN_Context* ctx) {
    if (fseek(ctx->output_fp, ctx->fp_pos - ctx->bytes_read, SEEK_SET) != 0) {
        return SPN_ERROR_FILE_READ;
    }
    if (fwrite(ctx->data, ctx->bytes_read, 1, ctx->output_fp) != 1) {
        return SPN_ERROR_FILE_WRITE;
    }
    if (fflush(ctx->output_fp) == EOF) {
        return SPN_ERROR_FILE_WRITE;
    }

    return SPN_SUCCESS;
}

spn_error_t spn_final(SPN_Context* ctx) {
    FILE* final_output_fp;
    uint8_t padding_size = 0;
    long int file_size;
    uint8_t copy_buffer[4096];
    size_t bytes_to_copy;
    size_t chunk_size;

    final_output_fp = fopen(ctx->target_output_file_path, "w+b");
    if (final_output_fp == NULL) {
        return SPN_ERROR_FILE_OPEN;
    }

    if (ctx->mode == 'd') {
        if (fseek(ctx->output_fp, -1, SEEK_END) != 0) {
            return SPN_ERROR_FILE_READ;
        }
        fread(&padding_size, 1, 1, ctx->output_fp);
        if (ferror(ctx->output_fp)) {
            return SPN_ERROR_FILE_READ;
        }
    }

    if (fseek(ctx->output_fp, 0, SEEK_END) != 0) {
        return SPN_ERROR_FILE_READ;
    }
    file_size = ftell(ctx->output_fp);
    if (file_size == -1) {
        return SPN_ERROR_FILE_READ;
    }
    if (fseek(ctx->output_fp, 0, SEEK_SET) != 0) {
        return SPN_ERROR_FILE_READ;
    }

    bytes_to_copy = file_size > padding_size ? file_size - padding_size : file_size;
    while (bytes_to_copy > 0) {
        chunk_size = bytes_to_copy > sizeof(copy_buffer) ? sizeof(copy_buffer) : bytes_to_copy;

        fread(copy_buffer, 1, chunk_size, ctx->output_fp);
        if (ferror(ctx->output_fp)) {
            return SPN_ERROR_FILE_READ;
        }

        if (fwrite(copy_buffer, chunk_size, 1, final_output_fp) != 1) {
            return SPN_ERROR_FILE_WRITE;
        }

        bytes_to_copy -= chunk_size;
    }

    fclose(final_output_fp);

    return SPN_SUCCESS;
}

void spn_cleanup(SPN_Context* ctx) {
    for (int i = 0; i < NUMBER_OF_ROUNDS; i++) {
        free(ctx->round_keys[i]);
        ctx->round_keys[i] = NULL;
    }

    free(ctx->sbox_map);
    free(ctx->pbox_map);
    ctx->sbox_map = NULL;
    ctx->pbox_map = NULL;

    if (ctx->output_fp != NULL) {
        fclose(ctx->output_fp);
        ctx->output_fp = NULL;
    }

    remove(ctx->temp_output_file_path);
    free(ctx->temp_output_file_path);
    ctx->temp_output_file_path = NULL;
}
