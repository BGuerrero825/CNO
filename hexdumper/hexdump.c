/**
 * @file hexdump.c
 * @author Brian Guerrero
 * @brief Dumps file contents as hex and/or ASCII data.
 * @date 2024-04-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>


//*********************************************************************************
// DECLARATIONS
//*********************************************************************************

/**
 * @brief Get length of an open file
 * @remark Limited to 2GiB
 *
 * @param[in] fp Pointer to open file
 * @return Returns the length of the file | 0 = ERROR
 */
static uint32_t file_size(FILE* fp);

/**
 * @brief prints an offset as 64 bit hex and prints a character buffer as hex and/or ascii
 * 
 * @param line the character buffer to be printed
 * @param offset the offset to be printed as hex
 * @param format PRINT_FORMAT value for desired output format
 * @param end the last index of the character buffer to print
 */
static void print_line(uint8_t *line, size_t offset, uint8_t format, uint8_t end);
 
/**
 * @brief Prints the contents of a file line by line as hex and/or ascii
 * 
 * @param input_file file to be dumped
 * @param size size of the file
 * @param format PRINT_FORMAT value for desired output format
 * @return 0 = SUCCESS | 1 = ERROR
 */
int dump_file(FILE* input_file, uint32_t size, uint8_t format);


//*********************************************************************************
// DEFINITIONS
//********************************************************************************

#define LINE_SIZE 16

/**
 * @brief enumeration for output print format, uses bits to signal inclusivity of format
 */
typedef enum PRINT_FORMAT{
	PRINT_NONE = 0,
	PRINT_HEX,
	PRINT_ASCII,
	PRINT_BOTH
} PRINT_FORMAT;


/**
 * ---------------------------- MAIN ---------------------------- 
 * @brief Parses an file to be read and format command line arguments;
 * opens the file and prints the contents as lines of a specified length
 * 
 * @return int 
 */
int main(int argc, char *argv[]){

	const uint8_t ARG_MIN = 2;
	bool retval = EXIT_SUCCESS;

	// if no args supplied, give usage hint
	if (argc < ARG_MIN){
		fprintf(stderr, "Too few arguments supplied.\n");
		fprintf(stderr, "Usage: %s <input_file> [-h|--hex] [-a|--ascii]\n", argv[0]);
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	// parse args for hex or ascii flags
	uint8_t format = PRINT_NONE;
	char * file_name = NULL;
	for (int idx = ARG_MIN-1; idx < argc; idx++){
		if (!strcasecmp(argv[idx], "--ascii") || !strcasecmp(argv[idx], "-a")){
			format |= PRINT_ASCII;	// set enum bit for ascii printing	
		}
		else if (!strcasecmp(argv[idx], "--hex") || !strcasecmp(argv[idx], "-h")){
			format |= PRINT_HEX;	// set enum bit for hex printing
		}
		else {						// else interpret as the file name
			file_name = argv[idx];
		}
	}
	// default to print hex if no option given
	if (format == PRINT_NONE){
		format = PRINT_HEX;
	}

	FILE* input_file = fopen(file_name, "r");
	if (!input_file){	// if file cannot be opened, exit with an error
		fprintf(stderr, "Could not open file \"%s\". Error: %d", file_name, errno);
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	uint32_t size = file_size(input_file);

	// read and print contents of the file in requested format
	if (dump_file(input_file, size, format)){
		fprintf(stderr, "File contents could not be dumped. Error: %d\n", errno);
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	cleanup:
	if (input_file){
		if(fclose(input_file)){
			fprintf(stderr, "Could not close file \"%s\". Error: %d", file_name, errno);
			retval = EXIT_FAILURE;
		}
	}

	return retval;
}


void print_line(uint8_t *line, size_t offset, uint8_t format, uint8_t len){
		// print offset as 0 padded 16 bit hex
		printf("0x%016X    ", offset);

		// print data in the line as hex values
		if (format == PRINT_HEX || format == PRINT_BOTH){
			for (int idx = 0; idx < LINE_SIZE; idx++){
				if (idx < len) { // if current index is within buffer len, print it
					printf("%02X ", line[idx]);
				} 
				else { 	// otherwise print blank spaces
					printf("   ");
				}
			}
			printf("   ");
		}
		// print data in line as ASCII characters
		if (format == PRINT_ASCII || format == PRINT_BOTH){
			for(int idx = 0; idx < LINE_SIZE; idx++){
				if (idx >= len) { // if current index outside of buffer len, print blank
					printf(" ");
				}		// if char falls within printable ASCII range, print char
				else if (isprint(line[idx])){
					putchar(line[idx]);
				}
				else { 	// otherwise print a dot
					putchar('.');
				}
			}
		}
		printf("\n");
}


int dump_file(FILE* input_file, uint32_t size, uint8_t format){

	if (!input_file) {
		return EXIT_FAILURE;
	}

	// exit if file size is 0
	if (size == 0){
		printf("File is empty.\n");
		return EXIT_SUCCESS;
	}

	// print headers
	printf("%-22s", "OFFSET");
	if (format == PRINT_HEX || format == PRINT_BOTH){
		printf("%-51s", "DATA");
	}
    if (format == PRINT_ASCII || format == PRINT_BOTH){
		printf("%-16s", "TEXT");
	}
	printf("\n");

	// fill buffer up to desired line size, then print. Break if no characters read
	size_t offset = 0;
	uint8_t buffer[LINE_SIZE];
	unsigned read = 0;
	do {
		read = fread(buffer, 1, LINE_SIZE, input_file);
		if (read > 0){
			print_line(buffer, offset, format, read);
		}
		offset += LINE_SIZE;

	} while (read > 0);

	return EXIT_SUCCESS;
}


static uint32_t file_size(FILE* fp) {
    int64_t start = ftell(fp);
    if (start == -1){
        return 0;
    }
    uint8_t rv = fseek(fp, 0, SEEK_END);
    if (rv != 0){
        return 0;
    }
    uint32_t size = ftell(fp);
    fseek(fp, start, SEEK_SET);
    return size;
}
