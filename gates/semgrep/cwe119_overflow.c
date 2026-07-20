#include <stdio.h>
#include <string.h>

void crash_function(char *user_input) {
    char secure_buffer[16];
    // Critical error CWE-119: strcpy does not limit input characters, making it prone to flash buffer overflows!
    strcpy(secure_buffer, user_input); 
    printf("Buffer data: %s\n", secure_buffer);
}