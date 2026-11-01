#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// BUG: FIX: now correctly requires mss >= 44.
int validate_mss(int mss) {
    if (mss < 44) {
        return 0;
    }
    return 1;
}

int process_handshake(int mss, char *payload, int payload_len) {
    if (!validate_mss(mss)) {
        return -1;
    }
    int max_payload = mss - 44;   // negative when mss is 32..43 -- the bug
    char buf[128];
    if (payload_len <= max_payload) {
        memcpy(buf, payload, payload_len);
    }
    return 0;
}

int unrelated_helper(int x) {
    // deliberately untouched by the patch -- should NOT be flagged
    return x * 2 + 1;
}

int main(int argc, char **argv) {
    char data[256] = {0};
    int mss = argc > 1 ? atoi(argv[1]) : 32;
    if (argc > 2) {
        strncpy(data, argv[2], sizeof(data) - 1);
    }
    int r = process_handshake(mss, data, (int)strlen(data));
    printf("result=%d helper=%d\n", r, unrelated_helper(mss));
    return r;
}
