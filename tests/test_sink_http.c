#include <check.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdio.h>

#include "sink.h"
#include "strbuf.h"

/* Helper functions to be tested */
bool _key_exists_in_query_string(const char* key, const char* query_string);
strbuf* _serialize_json_object(json_t* jobject,
                               const char* name,
                               CURL* curl);
void _serialize_kv(strbuf* buf, const char* key, const char* value, CURL* curl);
void _serialize_parameters(strbuf* buf, const char* partition, kv_config* params, CURL* curl);


START_TEST(test_key_exists_in_query_string)
{
    fail_unless(_key_exists_in_query_string("key", "test_string_key") == false);
    fail_unless(_key_exists_in_query_string("key", "test_string_key=1") == false);
    fail_unless(_key_exists_in_query_string("key", "test_string_key_abc") == false);
    fail_unless(_key_exists_in_query_string("key", "test_string_key_abc=1") == false);
    fail_unless(_key_exists_in_query_string("", "test_string_key_abc=1") == false);
    fail_unless(_key_exists_in_query_string("", "") == false);
    fail_unless(_key_exists_in_query_string("long_key", "k=v") == false);
    fail_unless(_key_exists_in_query_string("long_key", "") == false);

    fail_unless(_key_exists_in_query_string("key", "key") == true);
    fail_unless(_key_exists_in_query_string("key", "key=5") == true);
    fail_unless(_key_exists_in_query_string("key", "key&key1") == true);
    fail_unless(_key_exists_in_query_string("key", "key=5&key1=1") == true);
}
END_TEST

START_TEST(test_serialize_json_object) {
    json_t* obj = json_object();
    CURL* curl = curl_easy_init();

    /* Empty json object */
    strbuf* buf = _serialize_json_object(obj, "json", curl);
    fail_unless(buf == NULL);

    /* Non-empty json object */
    json_object_set_new(obj, "test_real", json_real(100.0));
    json_object_set_new(obj, "test_int", json_integer(101));
    buf = _serialize_json_object(obj, "json", curl);
    fail_unless(buf != NULL);
    int len;
    char* data = strbuf_get(buf, &len);
    fail_unless(len == 66);

    const char* toCompare1 = "json=%7B%22test_real%22%3A%20100.0%2C%20%22test_int%22%3A%20101%7D";
    const char* toCompare2 = "json=%7B%22test_int%22%3A%20101%2C%20%22test_real%22%3A%20100.0%7D";
    fail_unless(strcmp(data, toCompare1) == 0 || strcmp(data, toCompare2) == 0);

    curl_easy_cleanup(curl);
    strbuf_free(buf, true);
    json_decref(obj);
}
END_TEST

START_TEST(test_build_full_name) {
    char buffer[128];  // Enough for the tests.
    // No prefix when prefix is NULL or pre_len is 0.
    _build_full_name(buffer, NULL, 0, "test_metric", 11);
    fail_unless(strcmp(buffer, "test_metric") == 0);
    _build_full_name(buffer, "dummy_", 0, "test_metric", 11);
    fail_unless(strcmp(buffer, "test_metric") == 0);
    _build_full_name(buffer, NULL, 100, "test_metric", 11);
    fail_unless(strcmp(buffer, "test_metric") == 0);
    // Build correct full name if pre_len is not the length of string.
    _build_full_name(buffer, "dummy_extra_character", 6, "test_metric", 11);
    fail_unless(strcmp(buffer, "dummy_test_metric") == 0);
    _build_full_name(buffer, "dummy_", 100, "test_metric", 11);
    fail_unless(strcmp(buffer, "dummy_test_metric") == 0);

    // Build correct full name if name_len is less than the number of characters in name.
    _build_full_name(buffer, "dummy_", 6, "test_metric_with_extra_character", 11);
    fail_unless(strcmp(buffer, "dummy_test_metric") == 0);
    // Build correct full name if name_len is greater than the number of characters in name.
    _build_full_name(buffer, "dummy_", 6, "test_metric_with_extra_character", 100);
    fail_unless(strcmp(buffer, "dummy_test_metric_with_extra_character") == 0);
}
END_TEST

START_TEST(test_serialize_kv) {
    strbuf* buf;
    int len;
    char* data;

    strbuf_new(&buf, 0);
    /* A basic case */
    _serialize_kv(buf, "abc", "<123", NULL);
    data = strbuf_get(buf, &len);
    fail_unless(len == 8);
    fail_unless(strcmp(data, "abc=<123") == 0);

    /* Key can be NULL */
    _serialize_kv(buf, NULL, "123", NULL);
    data = strbuf_get(buf, &len);
    fail_unless(len == 12);
    fail_unless(strcmp(data, "abc=<123&123") == 0);

    /* Value supports escaping */
    CURL* curl = curl_easy_init();
    _serialize_kv(buf, "abc", "<123", curl);
    data = strbuf_get(buf, &len);
    fail_unless(len == 23);
    fail_unless(strcmp(data, "abc=<123&123&abc=%3C123") == 0);

    curl_easy_cleanup(curl);
    strbuf_free(buf, true);
}
END_TEST

START_TEST(test_serialize_parameters) {
    strbuf* buf;
    int len;
    char* data;
    kv_config test_data[2];

    /* Set up kv config list */
    test_data[0].section = "";
    test_data[0].k = "key1";
    test_data[0].v = "value1";
    test_data[0].next = &test_data[1];
    test_data[1].section = "";
    test_data[1].k = "key2";
    test_data[1].v = "value2";
    test_data[1].next = NULL;

    /* With empty partition string */
    strbuf_new(&buf, 0);
    _serialize_parameters(buf, "", test_data, NULL);
    data = strbuf_get(buf, &len);
    fail_unless(len == 23);
    fail_unless(strcmp(data, "key1=value1&key2=value2") == 0);
    strbuf_free(buf, true);

    /* With non-empty partition string */
    strbuf_new(&buf, 0);
    _serialize_parameters(buf, "key1=123", test_data, NULL);
    data = strbuf_get(buf, &len);
    fail_unless(len == 20);
    fail_unless(strcmp(data, "key1=123&key2=value2") == 0);
    strbuf_free(buf, true);
}
END_TEST
