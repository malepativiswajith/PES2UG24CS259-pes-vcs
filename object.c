// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTATION ─────────────────────────────────────────────────────────

static const char *type_str(ObjectType t) {
    if (t == OBJ_BLOB) return "blob";
    if (t == OBJ_TREE) return "tree";
    return "commit";
}

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str(type), len) + 1;

    size_t total = header_len + len;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    memcpy(buf, header, header_len);
    memcpy(buf + header_len, data, len);

    compute_hash(buf, total, id_out);

    if (object_exists(id_out)) {
        free(buf);
        return 0;
    }

    char path[512];
    object_path(id_out, path, sizeof(path));

    char dir[512];
    strcpy(dir, path);
    char *slash = strrchr(dir, '/');
    *slash = '\0';

    mkdir(OBJECTS_DIR, 0755);
    mkdir(dir, 0755);

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(buf);
        return -1;
    }

    write(fd, buf, total);
    fsync(fd);
    close(fd);

    rename(tmp, path);
    free(buf);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);

    uint8_t *buf = malloc(size);
    fread(buf, 1, size, fp);
    fclose(fp);

    ObjectID check;
    compute_hash(buf, size, &check);

    if (memcmp(check.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    char *null = memchr(buf, '\0', size);
    if (!null) {
        free(buf);
        return -1;
    }

    if (strncmp((char*)buf, "blob", 4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char*)buf, "tree", 4) == 0) *type_out = OBJ_TREE;
    else *type_out = OBJ_COMMIT;

    size_t header_len = (null - (char*)buf) + 1;
    *len_out = size - header_len;

    *data_out = malloc(*len_out);
    memcpy(*data_out, buf + header_len, *len_out);

    free(buf);
    return 0;
}
