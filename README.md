Multi-threaded file hashing tool with custom assembly-optimized hash functions for filesystem analysis and integrity verification.

## Prequests;

- GCC compiler with C11 support
- GNU Assembler (as)
- pthread library
- x86-64 architecture

## Platform-Specific Requirements;

**Linux/macOS:**
- POSIX-compliant system
- GCC or Clang

**Windows:**
- MinGW-w64 or similar GCC port
- Make utility (MinGW32-make or GNU Make)

## Build;

**Linux/macOS:**
```bash
make
```

**Windows (MinGW):**
```bash
mingw32-make
```

This generates the `hash` executable (or `hash.exe` on Windows).


## Usage;

### Basic Usage
```bash
./hash <directory>
```

Processes all files in the specified directory recursively and generates a hash report.

### With Configuration File
```bash
./hash <directory> <config_file>
```

The configuration file supports the following parameter:
```
hash_size=<value>
```

Valid range: 256 to 1048576

Example config.txt:
```
hash_size=2048
```

## Output;

The program generates a report file named `<directory>.report` containing:

- List of all processed files
- 64-bit hash value for each file in hexadecimal format

Terminal output includes:
- Number of files found
- Number of batches processed
- Hash table statistics (size, utilization, collision count)

## Architecture;

### Hash Algorithm

The hash computation uses three assembly functions in `hash.S`:

1. **asm_hash_block**: Primary hash function using multiplicative hashing with bit rotation
2. **asm_transform**: Data transformation layer with XOR and rotation operations
3. **asm_checksum**: XOR-based checksum with rotation for verification

Hash values are computed as: `hash = asm_hash_block(data) XOR asm_checksum(asm_transform(data))`

The assembly code supports both Windows (Microsoft x64) and Linux (System V AMD64) calling conventions through conditional compilation.

### Threading Model;

- Files are processed in batches (default: 8 files per batch)
- Each file in a batch gets a dedicated worker thread
- Maximum batch size: 32 threads
- Thread-safe hash table operations with mutex locks

### Hash Table;

- Uses linear probing for collision resolution
- Automatic load factor enforcement (75% maximum)
- Thread-safe insert and lookup operations
- Statistical analysis of collision rates

## Limitations;

- Maximum file size: 1 GB
- Maximum files processed: 100,000
- Maximum path length: 4096 characters
- Maximum recursion depth: 32 levels
- Hash table size range: 256 to 1,048,576 slots

## Error Handling;

The program validates:
- Directory existence and accessibility
- File size constraints
- Path length limits
- Memory allocation success
- Thread creation success
- Configuration file parameters

Errors are reported to stderr with descriptive messages.

>[!WARNING]
>This is a custom hash algorithm designed for file identification and integrity checking. It is not a cryptographic hash function and should not be used for security applications requiring collision resistance or preimage resistance.
>
>This software is provided as-is for educational and analysis purposes.
