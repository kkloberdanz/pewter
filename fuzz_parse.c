/*
 * libFuzzer harness: runs arbitrary bytes through pewter's request parser
 * in-process (parse_request, parse_headers, sanitize_path, url_encode_path,
 * content_type, log_safe) under ASan/UBSan.  Needs clang with libFuzzer
 * (Linux: the libclang-rt-dev package).
 *
 *   make fuzz
 *   ./pewter-fuzz -max_len=9000 -timeout=5 -max_total_time=120 corpus/
 */
#define main pewter_main
#include "pewter.c"
#undef main

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char req[REQ_BUF_SIZE];
    char clean[MAX_PATH_LEN];
    char enc[ENC_PATH_LEN];
    char safe[LOG_TARGET_LEN];
    const char *method = "-";
    char *target = NULL;
    char *hdrs = NULL;
    int is_head = 0;
    int http11 = 0;
    int trailing = 0;
    int status;

    /* read_request() never stores more than REQ_BUF_SIZE - 1 bytes and
       rejects NUL bytes before parsing, so mirror that here. */
    if (size > sizeof req - 1)
        size = sizeof req - 1;
    if (memchr(data, '\0', size) != NULL)
        return 0;
    memcpy(req, data, size);
    req[size] = '\0';

    status = parse_request(req, &method, &target, &is_head, &http11, &hdrs);
    if (status == 0)
        status = parse_headers(hdrs, http11);
    if (status == 0)
        status = sanitize_path(target, clean, sizeof clean, &trailing);
    if (status == 0) {
        (void)url_encode_path(clean, enc, sizeof enc);
        (void)content_type(clean);
    }
    log_safe(target != NULL ? target : "-", safe, sizeof safe);
    return 0;
}
