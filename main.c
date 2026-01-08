#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <dirent.h>
#else
#include <windows.h>
#endif
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>

#define MAX_PATH_LENGTH 4096
#define MAX_FILES 100000
#define MAX_BATCH_SIZE 32
#define MAX_FILE_SIZE (1024ULL * 1024 * 1024)
#define MIN_HASH_TABLE_SIZE 256
#define MAX_HASH_TABLE_SIZE 1048576
#define MAX_RECURSION_DEPTH 32

extern uint64_t asm_hash_block(uint8_t* data, size_t len, uint64_t seed);
extern void asm_transform(uint8_t* buffer, size_t size);
extern uint64_t asm_checksum(void* ptr, int count);

typedef struct {
    char* filename;
    uint64_t hash;
    size_t size;
    int priority;
} FileEntry;

typedef struct {
    uint8_t* buffer;
    size_t length;
    uint64_t result;
    int thread_id;
    int success;
} ThreadData;

typedef struct {
    char** file_list;
    int file_count;
    int capacity;
    pthread_mutex_t lock;
} FileList;

typedef struct {
    uint64_t* table;
    size_t size;
    size_t used;
    pthread_mutex_t lock;
} HashTable;

static FileList g_files = {NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER};
static HashTable g_hash_table = {NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER};

static int init_file_list(FileList* list, int initial_capacity) {
    if (initial_capacity <= 0 || initial_capacity > MAX_FILES) {
        return -1;
    }
    
    list->file_list = calloc(initial_capacity, sizeof(char*));
    if (!list->file_list) {
        return -1;
    }
    
    list->capacity = initial_capacity;
    list->file_count = 0;
    return 0;
}

static int add_file_to_list(FileList* list, const char* filename) {
    if (!list || !filename || strlen(filename) == 0) {
        return -1;
    }
    
    if (strlen(filename) >= MAX_PATH_LENGTH) {
        return -1;
    }
    
    pthread_mutex_lock(&list->lock);
    
    if (list->file_count >= list->capacity) {
        if (list->capacity >= MAX_FILES) {
            pthread_mutex_unlock(&list->lock);
            return -1;
        }
        
        int new_capacity = list->capacity * 2;
        if (new_capacity > MAX_FILES) {
            new_capacity = MAX_FILES;
        }
        
        char** new_list = realloc(list->file_list, sizeof(char*) * new_capacity);
        if (!new_list) {
            pthread_mutex_unlock(&list->lock);
            return -1;
        }
        
        list->file_list = new_list;
        list->capacity = new_capacity;
    }
    
    size_t filename_len = strlen(filename);
    if (filename_len >= MAX_PATH_LENGTH) {
        filename_len = MAX_PATH_LENGTH - 1;
    }
    
    list->file_list[list->file_count] = malloc(filename_len + 1);
    if (!list->file_list[list->file_count]) {
        pthread_mutex_unlock(&list->lock);
        return -1;
    }
    
    memcpy(list->file_list[list->file_count], filename, filename_len);
    list->file_list[list->file_count][filename_len] = '\0';
    
    list->file_count++;
    pthread_mutex_unlock(&list->lock);
    return 0;
}

static void free_file_list(FileList* list) {
    if (!list) {
        return;
    }
    
    pthread_mutex_lock(&list->lock);
    
    for (int i = 0; i < list->file_count; i++) {
        free(list->file_list[i]);
    }
    free(list->file_list);
    
    list->file_list = NULL;
    list->file_count = 0;
    list->capacity = 0;
    
    pthread_mutex_unlock(&list->lock);
}

static int init_hash_table(HashTable* ht, size_t size) {
    if (size < MIN_HASH_TABLE_SIZE || size > MAX_HASH_TABLE_SIZE) {
        return -1;
    }
    
    ht->table = calloc(size, sizeof(uint64_t));
    if (!ht->table) {
        return -1;
    }
    
    ht->size = size;
    ht->used = 0;
    return 0;
}

static int hash_table_insert(HashTable* ht, uint64_t hash) {
    if (!ht || !ht->table || hash == 0) {
        return -1;
    }
    
    pthread_mutex_lock(&ht->lock);
    
    if (ht->used >= ht->size * 0.75) {
        pthread_mutex_unlock(&ht->lock);
        return -1;
    }
    
    size_t slot = hash % ht->size;
    
    for (size_t i = 0; i < ht->size; i++) {
        size_t probe = (slot + i) % ht->size;
        if (ht->table[probe] == 0) {
            ht->table[probe] = hash;
            ht->used++;
            pthread_mutex_unlock(&ht->lock);
            return 0;
        }
        if (ht->table[probe] == hash) {
            pthread_mutex_unlock(&ht->lock);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&ht->lock);
    return -1;
}



static void free_hash_table(HashTable* ht) {
    if (!ht) {
        return;
    }
    
    pthread_mutex_lock(&ht->lock);
    free(ht->table);
    ht->table = NULL;
    ht->size = 0;
    ht->used = 0;
    pthread_mutex_unlock(&ht->lock);
}

static void* worker_thread(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    
    if (!data || !data->buffer) {
        if (data) {
            data->success = 0;
        }
        return NULL;
    }
    
    uint64_t hash = 0;
    uint8_t* working_buffer = malloc(data->length);
    
    if (!working_buffer) {
        data->success = 0;
        return NULL;
    }
    
    memcpy(working_buffer, data->buffer, data->length);
    
    for (size_t i = 0; i < data->length; i++) {
        size_t len = data->length - i;
        if (len > 0) {
            hash ^= asm_hash_block(&working_buffer[i], len, hash);
        }
    }
    
    data->result = hash;
    data->success = 1;
    
    free(working_buffer);
    return NULL;
}

static uint64_t compute_file_hash(const char* filename) {
    if (!filename) {
        return 0;
    }
    
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return 0;
    }
    
    if (st.st_size < 0 || (uint64_t)st.st_size > MAX_FILE_SIZE) {
        close(fd);
        return 0;
    }
    
    size_t file_size = (size_t)st.st_size;
    if (file_size == 0) {
        close(fd);
        return 0xDEADBEEF;
    }
    
    uint8_t* buffer = malloc(file_size);
    if (!buffer) {
        close(fd);
        return 0;
    }
    
    ssize_t bytes_read = 0;
    ssize_t total_read = 0;
    
    while (total_read < (ssize_t)file_size) {
        bytes_read = read(fd, buffer + total_read, file_size - total_read);
        if (bytes_read <= 0) {
            break;
        }
        total_read += bytes_read;
    }
    
    close(fd);
    
    if (total_read <= 0) {
        free(buffer);
        return 0;
    }
    
    uint64_t hash = asm_hash_block(buffer, (size_t)total_read, 0xDEADBEEF);
    
    uint8_t* transform_buffer = malloc((size_t)total_read);
    if (transform_buffer) {
        memcpy(transform_buffer, buffer, (size_t)total_read);
        asm_transform(transform_buffer, (size_t)total_read);
        
        int checksum_count = (int)((total_read) / 8);
        if (checksum_count > 0) {
            uint64_t checksum = asm_checksum(transform_buffer, checksum_count);
            hash ^= checksum;
        }
        
        free(transform_buffer);
    }
    
    free(buffer);
    return hash;
}

static int validate_path(const char* path) {
    if (!path || strlen(path) == 0) {
        return -1;
    }
    
    if (strlen(path) >= MAX_PATH_LENGTH) {
        return -1;
    }
    
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    
#ifdef _WIN32
    if (!(st.st_mode & _S_IFDIR)) {
        return -1;
    }
#else
    if (!S_ISDIR(st.st_mode)) {
        return -1;
    }
#endif
    
    return 0;
}

static int scan_directory_recursive(const char* path, FileList* list, int depth) {
    if (depth > MAX_RECURSION_DEPTH) {
        return 0;
    }
    
    if (!path || strlen(path) >= MAX_PATH_LENGTH) {
        return -1;
    }
    
#ifdef _WIN32
    WIN32_FIND_DATAA find_data;
    HANDLE hFind;
    char search_path[MAX_PATH_LENGTH];
    
    int written = snprintf(search_path, sizeof(search_path), "%s\\*", path);
    if (written < 0 || written >= (int)sizeof(search_path)) {
        return -1;
    }
    
    hFind = FindFirstFileA(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    int count = 0;
    do {
        if (strcmp(find_data.cFileName, ".") == 0 || 
            strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }
        
        char full_path[MAX_PATH_LENGTH];
        written = snprintf(full_path, sizeof(full_path), "%s\\%s", path, find_data.cFileName);
        if (written < 0 || written >= (int)sizeof(full_path)) {
            continue;
        }
        
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            int sub_count = scan_directory_recursive(full_path, list, depth + 1);
            if (sub_count > 0) {
                count += sub_count;
            }
        } else {
            if (add_file_to_list(list, full_path) == 0) {
                count++;
            }
        }
        
        if (list->file_count >= MAX_FILES) {
            break;
        }
    } while (FindNextFileA(hFind, &find_data) != 0);
    
    FindClose(hFind);
    return count;
#else
    DIR* dir = opendir(path);
    if (!dir) {
        return -1;
    }
    
    struct dirent* entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[MAX_PATH_LENGTH];
        int written = snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (written < 0 || written >= (int)sizeof(full_path)) {
            continue;
        }
        
        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }
        
        if (S_ISDIR(st.st_mode)) {
            int sub_count = scan_directory_recursive(full_path, list, depth + 1);
            if (sub_count > 0) {
                count += sub_count;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (add_file_to_list(list, full_path) == 0) {
                count++;
            }
        }
        
        if (list->file_count >= MAX_FILES) {
            break;
        }
    }
    
    closedir(dir);
    return count;
#endif
}

static int process_directory(const char* path, FileList* list) {
    if (validate_path(path) != 0) {
        return -1;
    }
    
    return scan_directory_recursive(path, list, 0);
}

static int process_file_batch(char** files, int count) {
    if (!files || count <= 0 || count > MAX_BATCH_SIZE) {
        return -1;
    }
    
    pthread_t* threads = calloc(count, sizeof(pthread_t));
    ThreadData* thread_data = calloc(count, sizeof(ThreadData));
    
    if (!threads || !thread_data) {
        free(threads);
        free(thread_data);
        return -1;
    }
    
    int threads_created = 0;
    
    for (int i = 0; i < count; i++) {
        thread_data[i].success = 0;
        thread_data[i].buffer = NULL;
        thread_data[i].length = 0;
        thread_data[i].thread_id = i;
        
        int fd = open(files[i], O_RDONLY);
        if (fd < 0) {
            continue;
        }
        
        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            continue;
        }
        
        if (st.st_size <= 0 || (uint64_t)st.st_size > MAX_FILE_SIZE) {
            close(fd);
            continue;
        }
        
        thread_data[i].length = (size_t)st.st_size;
        thread_data[i].buffer = malloc(thread_data[i].length);
        
        if (!thread_data[i].buffer) {
            close(fd);
            continue;
        }
        
        ssize_t bytes_read = read(fd, thread_data[i].buffer, thread_data[i].length);
        close(fd);
        
        if (bytes_read != (ssize_t)thread_data[i].length) {
            free(thread_data[i].buffer);
            thread_data[i].buffer = NULL;
            continue;
        }
        
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) == 0) {
            threads_created++;
        } else {
            free(thread_data[i].buffer);
            thread_data[i].buffer = NULL;
        }
    }
    
    for (int i = 0; i < count; i++) {
        if (thread_data[i].buffer) {
            pthread_join(threads[i], NULL);
            
            if (thread_data[i].success && thread_data[i].result != 0) {
                hash_table_insert(&g_hash_table, thread_data[i].result);
            }
            
            free(thread_data[i].buffer);
        }
    }
    
    free(threads);
    free(thread_data);
    
    return threads_created;
}

static int write_report(const char* output_file, FileList* list) {
    if (!output_file || !list) {
        return -1;
    }
    
    FILE* fp = fopen(output_file, "w");
    if (!fp) {
        return -1;
    }
    
    fprintf(fp, "Hash Report\n");
    fprintf(fp, "Total Files: %d\n\n", list->file_count);
    
    for (int i = 0; i < list->file_count; i++) {
        uint64_t hash = compute_file_hash(list->file_list[i]);
        fprintf(fp, "%s: %016" PRIx64 "\n", list->file_list[i], hash);
    }
    
    fclose(fp);
    return 0;
}

static int read_config(const char* config_file, size_t* hash_size) {
    if (!config_file || !hash_size) {
        return -1;
    }
    
    FILE* fp = fopen(config_file, "r");
    if (!fp) {
        return -1;
    }
    
    char line[256];
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "hash_size=", 10) == 0) {
            long value = strtol(line + 10, NULL, 10);
            if (value >= MIN_HASH_TABLE_SIZE && value <= MAX_HASH_TABLE_SIZE) {
                *hash_size = (size_t)value;
                found = 1;
            }
            break;
        }
    }
    
    fclose(fp);
    return found ? 0 : -1;
}

static void print_statistics(HashTable* ht) {
    if (!ht || !ht->table) {
        return;
    }
    
    pthread_mutex_lock(&ht->lock);
    
    size_t collisions = 0;
    
    for (size_t i = 0; i < ht->size; i++) {
        if (ht->table[i] != 0) {
            size_t expected_slot = ht->table[i] % ht->size;
            if (expected_slot != i) {
                collisions++;
            }
        }
    }
    
    printf("Hash table statistics:\n");
    printf("  Size: %zu\n", ht->size);
    printf("  Used: %zu (%.2f%%)\n", ht->used, 
           (double)ht->used / ht->size * 100.0);
    printf("  Collisions: %zu\n", collisions);
    
    pthread_mutex_unlock(&ht->lock);
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <directory> [config]\n", argv[0]);
        return 1;
    }
    
    size_t hash_table_size = 1024;
    
    if (argc == 3) {
        if (read_config(argv[2], &hash_table_size) != 0) {
            fprintf(stderr, "Warning: Failed to read config, using default size\n");
            hash_table_size = 1024;
        }
    }
    
    if (init_hash_table(&g_hash_table, hash_table_size) != 0) {
        fprintf(stderr, "Error: Failed to initialize hash table\n");
        return 1;
    }
    
    if (init_file_list(&g_files, 100) != 0) {
        fprintf(stderr, "Error: Failed to initialize file list\n");
        free_hash_table(&g_hash_table);
        return 1;
    }
    
    int files_found = process_directory(argv[1], &g_files);
    if (files_found < 0) {
        fprintf(stderr, "Error: Failed to process directory\n");
        free_file_list(&g_files);
        free_hash_table(&g_hash_table);
        return 1;
    }
    
    printf("Found %d files\n", g_files.file_count);
    
    if (g_files.file_count > 0) {
        int batch_size = 8;
        int batches = 0;
        
        for (int i = 0; i < g_files.file_count; i += batch_size) {
            int count = (i + batch_size > g_files.file_count) ? 
                        g_files.file_count - i : batch_size;
            
            if (process_file_batch(&g_files.file_list[i], count) > 0) {
                batches++;
            }
        }
        
        printf("Processed %d batches\n", batches);
    }
    
    char output_path[MAX_PATH_LENGTH];
    int written = snprintf(output_path, sizeof(output_path), "%s.report", argv[1]);
    
    if (written > 0 && written < (int)sizeof(output_path)) {
        if (write_report(output_path, &g_files) == 0) {
            printf("Report written to: %s\n", output_path);
        } else {
            fprintf(stderr, "Error: Failed to write report\n");
        }
    }
    
    print_statistics(&g_hash_table);
    
    free_file_list(&g_files);
    free_hash_table(&g_hash_table);
    
    return 0;
}