# Hexdump
Dumps a specified file's contents as hex and/or ASCII data.

## Building
If using GCC: `make` or `make run`

## Running
Build + Run: `make run`

Run (Windows/MinGW): `./hexdump.exe <input_file> [-h|--hex] [-a|--ascii]`

Run (Linux): `./hexdump <input_file> [-h|--hex] [-a|--ascii]`

---

## Roadmap
This roadmap section will serve as the instructions for this lab. While finishing the lab, feel free to remove this section from your README.

To practice what you have learned about memory, addresses, and pointers, you will be creating a commandline hexdump tool. This hexdump tool will take the following arguments:
- a path/filename of the file to dump
- any number of format flags that will determine the format of the output. 
    - <strong>-h/--hex</strong>: output the contents of the file as hex -- 2 uppercase digits for each byte with a space between bytes. THIS IS THE DEFAULT MODE IF NO FLAG IS GIVEN.
    - <strong>-a/--ascii</strong>: output the contents of the file as ascii -- print a '.' in place of each non-printable ASCII character.

Usage is as follows:
```
hexdump <file name> [flags]
```

Note:
- If no flag is given, printing hex is the default mode.
- If a flag is not recognized, ignore it
- Order of the flags does not matter -- if the ascii flag comes before the hex flag, hex will still be printed first as shown in the example below.

The output should go directly to `stdout`.

The "dump" of the file should print 16 bytes at a time, printing the 64-bit offset into the file at which those bytes are located followed by the data in the specific formats passed as flags to the application.

The following is an example of the expected output format:
```
OFFSET             DATA                                              TEXT
0x00000000000000   48 65 6C 6C 6F 2C 20 77 6F 72 6C 64 21 0A 00 00   Hello, world!...
0x00000000000010   CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC   ................
0x00000000000020   99 99 99 99 99 99 99 99 99 99 99 99 99            .............
```

The following are example uses:
```bash
hexdump file_name           # Should only display offset and hex
hexdump file_name -h        # Should only display offset and hex
hexdump file_name --ascii   # Should only display offset and ascii
hexdump file_name -a --hex  # Should display offset, hex, and ascii
hexdump file_name -t        # Invalid flag -- ignore it; display offset and hex
```

As always, don't forget to:
- Create a new branch for development off of the main branch
- MaGiC PBR (Makefile, .gitignore, Code; README with Purpose, Building, and Running sections)
    - After creating these files, create an initial commit with little to no content in it. This sets a baseline for each file before any work is done. 
- Commit after each logical set of changes (For example, after finishing a specific feature for your code).
- Create a pull request back into the master branch to submit your code
