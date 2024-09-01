# PST Password Remove
This is a **hacked together** PST password remover.

It can remove passwords from Outlook PST (Personal Storage Table / Outlook Personal Folders) files,
but not all Versions are implemented and the Checks might be insufficient to detect if we have a Version we can work with.
Therefore:

**Be aware it is barely testet, so backup your data before using it.**

Parts of the code are copied from [libpst](https://www.five-ten-sg.com/libpst/), as some Datastructures and functions are not exposed in the api.

And microsoft pst file [Documentation](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546).


## Compiling (on linux)
### Prerequisites
- C++ compiler (Supporting C++17, C Compiler, only tested with gcc 14.2.1)
- CMake
- libpst (Paths are still hardcoded, you might need to fix them in the CMakeLists.txt, tested with version 0.6.76-10 from arch repo)
- libz

### Compiling
   cd <directory where you have the source>
   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make

### Usage
- Backup your pst file

   ./pst_password_remove ./name-of-your-file.pst

- you should now have a name-of-your-file.pst.nopasswd rename it so the extension is .pst again
- You should now be able to open it without password in outlook

### Licensing
Parts from [libpst](https://www.five-ten-sg.com/libpst/) are GPL-2.0 .
