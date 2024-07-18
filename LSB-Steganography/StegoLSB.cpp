//-------------------------------------------------------------------------------------------------
// StegoLSB.cpp
// 
// Embed a payload into an image using LSB Steganography, or extract a payload that has been 
//  embedded in an image using LSB Steganography
//-------------------------------------------------------------------------------------------------
//#include <cstdint>
//#include <cstdbool>
//#include <cstdio>
#include <string>

#include "bmp_lsb.h"

//using namespace std;

//-------------------------------------------------------------------------------------------------
// Definitions and Types
//-------------------------------------------------------------------------------------------------
// action to perform
enum class Action {None, Store, Extract};

// application exit codes
#define EXITCODE_SUCCESS    0
#define EXITCODE_FAILURE    1

static const uint64_t MAX_FILE_SIZE = (100LL << 20); // sanity check for file size (100M)

static const unsigned MIN_ARGS = 3;     // minimum args is 3 (exe extract input-file)
static const unsigned MAX_ARGS = 5;     // max args is 5 (exe store input-file payload output-file)
static const char* USAGE = "Usage: StegoLSB <action> <input file> [<payload>] [<output-file>]\n"
"\n"
"            action     - action to perform (store (s) or extract (x))\n"
"            input file - image file to process\n"
"            payload    - file to embed in image\n"
"            output     - optionally specify output file, else output.BMP\n";


//-------------------------------------------------------------------------------------------------
// Function Declarations
//-------------------------------------------------------------------------------------------------
/**
 * @brief Parse arguments
 * 
 * @param[in] argc Count of command line arguments, including name of exe executing
 * @param[in] argv Array of command line arguments
 * @param[out] action Action to perform
 * @param[out] inFileName Name of image file to process
 * @param[out] outFileName Name of output file to write results to 
 * @param[out] payloadFileName Payload to embed, if action is store
 * @return Returns true if parse is successful, else show usage info and exit
 */
static bool ParseArgs(unsigned argc, char *argv[], Action &action, const char* &inFileName, const char* &outFileName, const char* &payloadFileName);

/**
 * @brief Attempt to encode a payload into a BMP image, return true if successful
 * 
 * @param[in] inFileName Path and name of image file to embed payload into
 * @param[in] outFileName Path and name of image file to write the results to
 * @param[in] payloadFileName Path and name of the payload to embed (need not be an image)
 */
static bool DoEncode(const char* inFileName, const char* outFileName, const char* payloadFileName);

/**
 * @brief Attempt to extract an encoded payload from a BMP image, return true if successful
 * 
 * @param[in] inFileName Path and name of image file to extract payload from
 * @param[in] outFileName Path and name of file to write extracted payload to
 */
static bool DoExtract(const char* inFileName, const char* outFileName);


//-------------------------------------------------------------------------------------------------
// Begin Code
//-------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    // default to failure code, set to success at the end of successful runs
    unsigned exitcode = EXITCODE_FAILURE;

    // parse and validate command line arguments
    Action action;
    const char* inFileName = nullptr;
    const char* outFileName = nullptr;
    const char* payloadFileName = nullptr;
    if (!ParseArgs(argc, argv, action, inFileName, outFileName, payloadFileName))
    {
        goto cleanup;
    }

    // Action::Store tells us to LSB encode the named payload into infile
    if (action == Action::Store)
    {
        if (DoEncode(inFileName, outFileName, payloadFileName))
        {
            exitcode = EXITCODE_SUCCESS;
        }
    }
    // Action::Extract tells us to extract an LSB encoded payload from infile and save it to disk
    else if (action == Action::Extract)
    {
        if (DoExtract(inFileName, outFileName))
        {
            exitcode = EXITCODE_SUCCESS;
        }
    }
    else
    {
        // ParseArgs() should have assured a valid action, but to be thorough, report this condition
        fprintf(stderr, "Unexpected Error: Invalid or unsupported action (%u)\n", static_cast<unsigned>(action));
    }

cleanup:
    if (exitcode != EXIT_SUCCESS)
    {
        printf("%s", USAGE);
    }
    return exitcode;
}


/**
 * @brief Compare two strings, return true if they match, case insensitively
 */
static bool StringsMatch(const char* str1, const char* str2)
{
    // return true for null argument if both are null, else return false
    if ((str1 == nullptr) || (str2 == nullptr))
    {
        return str1 == str2;
    }
    while(true)
    {
        // compares before checking for null terminator, so if one string is shorter, it will fail
        if (tolower(*str1) != tolower(*str2))
        {
            return false;
        }
        if (*str1 == 0)
        {
            break;
        }
        str1++;
        str2++;
    }
    
    return true;
}

/**
 * @brief Parse an action string
 *
 * @param arg Value given for action
 * @return Returns Action entered, or Action::None on failure
 */
static Action ParseAction(const char *arg)
{
    if (StringsMatch(arg, "s") || StringsMatch(arg, "store"))
    {
        return Action::Store;
    }
    if (StringsMatch(arg, "x") || StringsMatch(arg, "extract"))
    {
        return Action::Extract;
    }
    return Action::None;
}

#include <sys/stat.h>

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

/**
 * @brief See if a file exists
 *
 * @param[in] filePath Name, optionally including absolute or relative path, of file to check
 * @return Returns true if the file exists (not including directories)
 */
static bool IsFile(const char *const filePath)
{
    struct stat statbuf;

    if (stat(filePath, &statbuf) != 0)
    {
        return false;
    }
    return S_ISREG(statbuf.st_mode);
}


/**
 * @brief Get length of open file
 *
 * @remark Limited to 2G
 *
 * @param[in] fp Open file pointer
 * @return Returns the length of the file, on error returns -1
 */
static long FileSize(FILE* fp)
{
    long start = ftell(fp);
    if (start == -1)
    {
        return -1;
    }
    int rv = fseek(fp, 0, SEEK_END);
    if (rv != 0)
    {
        errno = rv;
        return -1;
    }
    long size = ftell(fp);
    fseek(fp, start, SEEK_SET);
    return size;
}


/** @brief Parse arguments (see details above) */
static bool ParseArgs(unsigned argc, char* argv[], Action& action, const char* &inFileName, const char* &outFileName, const char* &payloadFileName)
{
    action = Action::None;
    inFileName = nullptr;
    outFileName = nullptr;
    payloadFileName = nullptr;

    // Usage: StegoLSB <action> <input file> [<payload>] [<output-file>]
    // if incorrect number of arguments, just print usage
    if ((argc < MIN_ARGS) || (argc > MAX_ARGS))
    {
        fprintf(stderr, "ERROR: Wrong number of arguments: %d\n", argc);
        return false;
    }

    // process action
    if ((action = ParseAction(argv[1])) == Action::None)
    {
        fprintf(stderr, "ERROR: Unknown Action: '%s'\n", argv[1]);
        return false;
    }

    // process input file name
    if (!IsFile(argv[2]))
    {
        fprintf(stderr, "ERROR: Input File not found: '%s'\n", argv[2]);
        return false;
    }
    inFileName = argv[2];

    // for action == Store, argv[3] is payload, and argv[4] is optional output file, else argv[3] is optional output file
    unsigned outfileIndex;
    if (action == Action::Store)
    {
        outfileIndex = 4;
        if ((argc < 4) || !IsFile(argv[3]))
        {
            fprintf(stderr, "ERROR: Payload File not found: '%s'\n", argv[3]);
            return false;
        }
        payloadFileName = argv[3];
    }
    else
    {
        outfileIndex = 3;
        if (argc > 4)
        {
            fprintf(stderr, "ERROR: Too many arguments for Action Extract: '%u'\n", argc);
            return false;
        }
    }

    // process optional output file arg
    if (argc > outfileIndex)
    {
        outFileName = argv[outfileIndex];
    }
    else
    {
        // if a BMP is being encoded, the output will be a bmp
        if (action == Action::Store)
        {
            outFileName = "output.bmp";
        }
        // otherwise, we don't know what the output is
        else
        {
            outFileName = "output.bin";
        }
    }
    return true;
}

/**
 * @brief Load an entire file into a buffer allocated by the function
 *
 * @remark Use free() to release buffer when no longer needed
 *
 * @param fileName Name and path of file to read
 * @param fileSize Size of file read
 * @return Returns Allocated buffer containing file, NULL on failure  (free() when no longer needed)
 */
static uint8_t *LoadFileToMemory(const char *fileName, uint32_t *fileSize)
{
    if (fileSize)
    {
        *fileSize = 0;
    }

    // open a handle to the file
    FILE* fp;
    if (fopen_s(&fp, fileName, "rb") != 0)
    {
        fprintf(stderr, "ERROR: Open input file for read failed (file='%s', error=%u)\n", fileName, errno);
        return nullptr;
    }

    // find the size of the file
    long size = FileSize(fp);
    if (size == -1)
    {
        fprintf(stderr, "ERROR: Get input file size file failed (file='%s', error=%u)\n", fileName, errno);
        fclose(fp);
        return nullptr;
    }

    if (fileSize)
    {
        *fileSize = size;
    }

    // allocate buffer for file
    uint8_t *buffer = static_cast<uint8_t *>(calloc(size, 1));
    if (buffer == nullptr)
    {
        fprintf(stderr, "ERROR: Allocate read buffer failed (error=%u)\n", errno);
        goto cleanup;
    }

    // block to limit scope of fread() return value
    {
        // read file
        size_t rv = fread(buffer, 1, size, fp);
        if (rv != (size_t)size)
        {
            fprintf(stderr, "ERROR: Read input file failed (error=%u)\n", ferror(fp));
            goto cleanup;
        }
    }
    fclose(fp);
    return buffer;

cleanup:
    fclose(fp);
    if (buffer != nullptr)
    {
        free(buffer);
    }
    if (fileSize)
    {
        *fileSize = 0;
    }
    return nullptr;
}

/**
 * @brief Writes a buffer to file, if file exists it is overwritten with new contents
 *
 * @param fileName Name and path of file to write to
 * @param buffer Buffer to write 
 * @param fileSize Size of file in bytes
 * @return Returns true on success, else false
 */
static bool WriteBufferToFile(const char *fileName, const uint8_t *buffer, uint32_t fileSize)
{
    if (buffer == nullptr)
    {
        fprintf(stderr, "ERROR: Invalid argument: buffer is nullptr\n");
        return false;
    }

    // open a handle to the file
    FILE* fp;
    if (fopen_s(&fp, fileName, "wb") != 0)
    {
        fprintf(stderr, "ERROR: Open output file for write failed (file='%s', error=%u)\n", fileName, errno);
        return false;
    }

    bool result = true;
    // write file
    size_t rv = fwrite(buffer, 1, fileSize, fp);
    if (rv != (size_t)fileSize)
    {
        fprintf(stderr, "ERROR: Write output file failed (error=%u)\n", ferror(fp));
        result = false;
    }

    fclose(fp);
    return result;
}


/**
 * @brief Attempt to encode a payload into a BMP image, return true if successful
 */
bool DoEncode(const char* inFileName, const char* outFileName, const char* payloadFileName)
{
    // define return value before any goto's. Default to failure, set to success at the end of successful runs
    bool retval = false;

    // declare initialized variables that will be used by cleanup code on exit
    uint8_t *payload = nullptr;
    uint8_t *image = nullptr;

    // load BMP to be processed
    uint32_t imageSize;
    image = LoadFileToMemory(inFileName, &imageSize);
    if (image == nullptr)
    {
        goto cleanup;
    }

    // load payload
    uint32_t payloadSize;
    payload = LoadFileToMemory(payloadFileName, &payloadSize);
    if (payload == nullptr)
    {
        goto cleanup;
    }
    
    // LSB encode payload into image (presumably a BMP image)
    if (!BMPWriteLSB(image, payload, payloadSize))
    {
        goto cleanup;
    }
    
    // write modified image to output file
    if (!WriteBufferToFile(outFileName, image, imageSize))
    {
        goto cleanup;
    }
    
    // report success and set return value to true
    retval = true;
    printf("Payload (%u bytes) successfully encoded into '%s' (%u bytes)\n", payloadSize, outFileName, imageSize);

cleanup:
    if (image != nullptr)
    {
        free(image);
    }
    if (payload != nullptr)
    {
        free(payload);
    }
    return retval;
}


/**
 * @brief Attempt to extract an encoded payload from a BMP image, return true if successful
 */
bool DoExtract(const char* inFileName, const char* outFileName)
{
    // define return value before any goto's. Default to failure, set to success at the end of successful runs
    bool retval = false;

    // declare initialized variables that will be used by cleanup code on exit
    uint8_t *payload = nullptr;
    uint8_t *image = nullptr;

    // load BMP to be processed
    uint32_t imageSize;
    image = LoadFileToMemory(inFileName, &imageSize);
    if (image == nullptr)
    {
        goto cleanup;
    }

    // attempt to extract an LSB encoded payload from the given image (presumably a BMP with a previously encoded payload)
    uint32_t payloadSize;
    if (!BMPReadLSB(image, payload, payloadSize))
    {
        goto cleanup;
    }

    // write payload
    if (!WriteBufferToFile(outFileName, payload, payloadSize))
    {
        goto cleanup;
    }

    // report success and set return value to true
    retval = true;
    printf("Payload (%u bytes) successfully exported to '%s' (%u bytes)\n", payloadSize, outFileName, imageSize);

cleanup:
    if (image != nullptr)
    {
        free(image);
    }
    if (payload != nullptr)
    {
        free(payload);
    }
    return retval;
}

