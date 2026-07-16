#include <stdint.h>


static __attribute__((noinline)) uint32_t
pow_sanitizer_misaligned_read(const uint8_t *p)
{
    const uint32_t  *value;

    value = (const uint32_t *) (p + 1);
    return *value;
}


int
main(void)
{
    union {
        uint32_t  alignment;
        uint8_t   bytes[sizeof(uint32_t) + 1];
    } storage = { 0 };

    return pow_sanitizer_misaligned_read(storage.bytes) == 0 ? 0 : 1;
}
