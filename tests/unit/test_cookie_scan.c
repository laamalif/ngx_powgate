#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pow_cookie_scan.h"
#include "pow_protocol.h"
#include "test.h"


typedef struct {
    const uint8_t  *field;
    size_t          field_len;
    const uint8_t  *name;
    size_t          name_len;
    size_t          found;
    size_t          offsets[3];
    size_t          lengths[3];
} scan_case_t;


static int
run_case(const scan_case_t *test)
{
    pow_cookie_scan_result_t  rc;
    pow_cookie_value_t        value;
    const uint8_t            *previous_end;
    size_t                    before, cursor, found;

    cursor = 0;
    found = 0;
    previous_end = test->field;

    for ( ;; ) {
        before = cursor;
        value.data = NULL;
        value.len = SIZE_MAX;

        rc = pow_cookie_scan_next(test->field, test->field_len,
                                  test->name, test->name_len,
                                  &cursor, &value);
        if (rc == POW_COOKIE_SCAN_DONE) {
            TEST_ASSERT(cursor == test->field_len);
            TEST_ASSERT(value.data == NULL);
            TEST_ASSERT(value.len == SIZE_MAX);
            break;
        }

        TEST_ASSERT(rc == POW_COOKIE_SCAN_FOUND);
        TEST_ASSERT(found < test->found);
        TEST_ASSERT(cursor > before);
        TEST_ASSERT(value.data >= test->field);
        TEST_ASSERT(value.data <= test->field + test->field_len);
        TEST_ASSERT(value.len <= test->field_len);
        TEST_ASSERT(value.data + value.len
                    <= test->field + test->field_len);
        TEST_ASSERT(value.data >= previous_end);
        TEST_ASSERT((size_t) (value.data - test->field)
                    == test->offsets[found]);
        TEST_ASSERT(value.len == test->lengths[found]);

        previous_end = value.data + value.len;
        found++;
        TEST_ASSERT(found <= test->field_len + 1);
    }

    TEST_ASSERT(found == test->found);

    return 0;
}


static int
test_table(void)
{
    static const uint8_t  name[] = POW_AUTH_COOKIE_NAME;
    static const uint8_t  embedded_nul[] =
        POW_AUTH_COOKIE_NAME "=a\0b;" POW_AUTH_COOKIE_NAME "=z";
    static const scan_case_t  cases[] = {
        {
            (const uint8_t *) POW_AUTH_COOKIE_NAME
                "=a;x=y; " POW_AUTH_COOKIE_NAME "=b",
            sizeof(POW_AUTH_COOKIE_NAME
                   "=a;x=y; " POW_AUTH_COOKIE_NAME "=b") - 1,
            name, sizeof(name) - 1, 2,
            { 6, 19, 0 }, { 1, 1, 0 }
        },
        {
            (const uint8_t *) ";; " POW_AUTH_COOKIE_NAME "=;a=b;;",
            sizeof(";; " POW_AUTH_COOKIE_NAME "=;a=b;;") - 1,
            name, sizeof(name) - 1, 1,
            { 9, 0, 0 }, { 0, 0, 0 }
        },
        {
            (const uint8_t *) " \t" POW_AUTH_COOKIE_NAME
                "=x;\t" POW_AUTH_COOKIE_NAME "=y",
            sizeof(" \t" POW_AUTH_COOKIE_NAME
                   "=x;\t" POW_AUTH_COOKIE_NAME "=y") - 1,
            name, sizeof(name) - 1, 2,
            { 8, 17, 0 }, { 1, 1, 0 }
        },
        {
            (const uint8_t *) POW_AUTH_COOKIE_NAME
                " =bad;" POW_AUTH_COOKIE_NAME "=good",
            sizeof(POW_AUTH_COOKIE_NAME
                   " =bad;" POW_AUTH_COOKIE_NAME "=good") - 1,
            name, sizeof(name) - 1, 1,
            { 17, 0, 0 }, { 4, 0, 0 }
        },
        {
            (const uint8_t *) POW_AUTH_COOKIE_NAME
                "= value;" POW_AUTH_COOKIE_NAME "=\tvalue",
            sizeof(POW_AUTH_COOKIE_NAME
                   "= value;" POW_AUTH_COOKIE_NAME "=\tvalue") - 1,
            name, sizeof(name) - 1, 2,
            { 6, 19, 0 }, { 6, 6, 0 }
        },
        {
            (const uint8_t *) "__POW=a;" POW_AUTH_COOKIE_NAME
                "_extra=b;" POW_AUTH_COOKIE_NAME "=c",
            sizeof("__POW=a;" POW_AUTH_COOKIE_NAME
                   "_extra=b;" POW_AUTH_COOKIE_NAME "=c") - 1,
            name, sizeof(name) - 1, 1,
            { 28, 0, 0 }, { 1, 0, 0 }
        },
        {
            (const uint8_t *) "broken; =x;" POW_AUTH_COOKIE_NAME
                "=\"a,b\";tail",
            sizeof("broken; =x;" POW_AUTH_COOKIE_NAME
                   "=\"a,b\";tail") - 1,
            name, sizeof(name) - 1, 1,
            { 17, 0, 0 }, { 5, 0, 0 }
        },
        {
            embedded_nul, sizeof(embedded_nul) - 1,
            name, sizeof(name) - 1, 2,
            { 6, 16, 0 }, { 3, 1, 0 }
        },
        {
            (const uint8_t *) "", 0,
            name, sizeof(name) - 1, 0,
            { 0, 0, 0 }, { 0, 0, 0 }
        },
        {
            (const uint8_t *) "a=b;c=d", sizeof("a=b;c=d") - 1,
            name, sizeof(name) - 1, 0,
            { 0, 0, 0 }, { 0, 0, 0 }
        }
    };
    size_t  i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT(run_case(&cases[i]) == 0);
    }

    return 0;
}


static int
test_invalid_arguments(void)
{
    static const uint8_t      field[] = POW_AUTH_COOKIE_NAME "=value";
    static const uint8_t      name[] = POW_AUTH_COOKIE_NAME;
    pow_cookie_scan_result_t  rc;
    pow_cookie_value_t        value;
    size_t                    cursor;

    cursor = 3;
    value.data = field + 1;
    value.len = 7;

#define TEST_ERROR(call)                                                   \
    do {                                                                   \
        rc = (call);                                                       \
        TEST_ASSERT(rc == POW_COOKIE_SCAN_ERROR);                          \
        TEST_ASSERT(cursor == 3);                                          \
        TEST_ASSERT(value.data == field + 1);                              \
        TEST_ASSERT(value.len == 7);                                       \
    } while (0)

    TEST_ERROR(pow_cookie_scan_next(NULL, sizeof(field) - 1,
                                    name, sizeof(name) - 1,
                                    &cursor, &value));
    TEST_ERROR(pow_cookie_scan_next(field, sizeof(field) - 1,
                                    NULL, sizeof(name) - 1,
                                    &cursor, &value));
    TEST_ERROR(pow_cookie_scan_next(field, sizeof(field) - 1,
                                    name, 0, &cursor, &value));
    TEST_ERROR(pow_cookie_scan_next(field, 2, name, sizeof(name) - 1,
                                    &cursor, &value));

    rc = pow_cookie_scan_next(field, sizeof(field) - 1,
                              name, sizeof(name) - 1, NULL, &value);
    TEST_ASSERT(rc == POW_COOKIE_SCAN_ERROR);
    TEST_ASSERT(value.data == field + 1);
    TEST_ASSERT(value.len == 7);

    rc = pow_cookie_scan_next(field, sizeof(field) - 1,
                              name, sizeof(name) - 1, &cursor, NULL);
    TEST_ASSERT(rc == POW_COOKIE_SCAN_ERROR);
    TEST_ASSERT(cursor == 3);

#undef TEST_ERROR

    return 0;
}


int
main(void)
{
    TEST_ASSERT(test_table() == 0);
    TEST_ASSERT(test_invalid_arguments() == 0);

    puts("test_cookie_scan: PASS");
    return 0;
}
