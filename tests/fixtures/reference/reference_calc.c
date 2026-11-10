/* Nexonic ReForge Studio — Ground Truth Reference Application
 * Purpose: Legally authorized ground-truth reference fixture with documented functions,
 *          symbols, control-flow graphs, and interface contracts.
 */

#include <stdio.h>
#include <string.h>

#define STATUS_OK 0
#define STATUS_AUTH_FAILED 1
#define STATUS_OVERFLOW 2

int calc_add(int a, int b) {
    return a + b;
}

int calc_factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    int result = 1;
    for (int i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}

unsigned int calc_crc32(const unsigned char *data, int len) {
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

int authenticate_user(const char *username, const char *token) {
    if (!username || !token) {
        return STATUS_AUTH_FAILED;
    }
    if (strcmp(username, "admin") == 0 && strcmp(token, "ref_secret_99") == 0) {
        return STATUS_OK;
    }
    return STATUS_AUTH_FAILED;
}

int main(int argc, char **argv) {
    printf("[REF_APP] Ground Truth Reference Starting\n");
    if (argc < 2) {
        printf("Usage: reference_calc <add|fact|auth>\n");
        return 1;
    }

    if (strcmp(argv[1], "add") == 0) {
        printf("Result: %d\n", calc_add(40, 2));
    } else if (strcmp(argv[1], "fact") == 0) {
        printf("Factorial(5): %d\n", calc_factorial(5));
    } else if (strcmp(argv[1], "auth") == 0 && argc >= 4) {
        int res = authenticate_user(argv[2], argv[3]);
        printf("Auth: %s\n", res == STATUS_OK ? "SUCCESS" : "DENIED");
    }
    return 0;
}
