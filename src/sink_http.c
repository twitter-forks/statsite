#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <jansson.h>
#include <curl/curl.h>
#include <pthread.h>
#include <unistd.h>

#include "hashmap.h"
#include "lifoq.h"
#include "metrics.h"
#include "sink.h"
#include "strbuf.h"
#include "utils.h"

const int QUEUE_MAX_SIZE = 10 * 1024 * 1024; /* 10 MB of data */
const int DEFAULT_TIMEOUT_SECONDS = 30;
const useconds_t FAILURE_WAIT = 5000000; /* 5 seconds */
const int INITIAL_EXTRA_POST_BUFFER_SIZE = 128;

const char* DEFAULT_CIPHERS_NSS = "ecdhe_ecdsa_aes_128_gcm_sha_256,ecdhe_rsa_aes_256_sha,rsa_aes_128_gcm_sha_256,rsa_aes_256_sha,rsa_aes_128_sha";
const char* DEFAULT_CIPHERS_OPENSSL = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA";

const char* USERAGENT = "statsite-http/0";
const char* OAUTH2_GRANT = "grant_type=client_credentials";

char* DEFAULT_PARTITION = "";
int PARTITION_DELIMITER = '?';

/*
 * Data from the HTTP sink.
 */
struct http_sink {
    sink sink;
    lifoq* queue;
    pthread_t worker;
    char* oauth_bearer;
};

/*
 * Data from the metrics_iter callback.
 */
struct metric_cb_info {
    /* Map from partition string to metrics json object */
    hashmap* json_map;
    const statsite_config* config;
    const sink_config_http* httpconfig;
};

/*
 * Data from the hashmap_iter callback.
 */
struct jsonmap_cb_info {
    const char* metrics_name;
    const kv_config* params;
    const char* timestamp_name;
    const char* encoded_time;
    CURL* curl;
    struct http_sink* sink;
};

/**
 * Build full name for metric from prefix and metric names and store it
 * into a buffer.
 * @arg buffer The output buffer for the full name. It MUST have enough space.
 * @arg prefix The prefix string.
 * @arg pre_len The prefix string length.
 * @arg name The metirc key.
 * @arg name_len The metirc key length.
 */
static void _build_full_name(char* buffer,
                             const char* prefix,
                             int pre_len,
                             const char* name,
                             int name_len) {
    if (pre_len > 0 && prefix != NULL) {
        strncpy(buffer, prefix, pre_len);
        buffer[pre_len] = '\0';
        strncat(buffer, name, name_len);
    } else {
        strncpy(buffer, name, name_len);
        buffer[name_len] = '\0';
    }
}

/*
 * Add a metric into the output json object.
 * @arg obj The output json object.
 * @arg type The type of metrics.
 * @arg prefix The prefix string.
 * @arg pre_len The prefix string length.
 * @arg name The metirc key.
 * @arg name_len The metirc key length.
 * @arg value The metric value.
 * @arg config The statsite config.
 */
static void _add_metric_to_json(json_t* obj,
                                metric_type type,
                                const char* prefix,
                                int pre_len,
                                const char* name,
                                int name_len,
                                void* value,
                                const statsite_config* config) {
    /*
     * Scary looking macro to apply suffixes to a string, and then
     * insert them into a json object with a given value. Needs "suffixed"
     * in scope, with a "base_len" telling it how mmany chars the string is
     */
#define SUFFIX_ADD(suf, val)                                            \
    do {                                                                \
        suffixed[base_len - 1] = '\0';                                  \
        strcat(suffixed, suf);                                          \
        json_object_set_new(obj, suffixed, val);                        \
    } while(0)

    /* Using C99 stack allocation, don't panic */
    int base_len = name_len + pre_len + 1;
    char full_name[base_len];
    _build_full_name(full_name, prefix, pre_len, name, name_len);

    switch (type) {
    case KEY_VAL:
        json_object_set_new(obj, full_name, json_real(*(double*)value));
        break;
    case GAUGE:
        json_object_set_new(obj, full_name, json_real(*(double*)value));
        break;
    case COUNTER:
    {
        if (config->extended_counters) {
            /* We allow up to 8 characters for a suffix, based on the static strings below */
            const int suffix_space = 8;
            char suffixed[base_len + suffix_space];
            strcpy(suffixed, full_name);
            SUFFIX_ADD(".count", json_integer(counter_count(value)));
            SUFFIX_ADD(".mean", json_real(counter_mean(value)));
            SUFFIX_ADD(".stdev", json_real(counter_stddev(value))); /* stdev matches other output */
            SUFFIX_ADD(".sum", json_real(counter_sum(value)));
            SUFFIX_ADD(".sum_sq", json_real(counter_squared_sum(value)));
            SUFFIX_ADD(".lower", json_real(counter_min(value)));
            SUFFIX_ADD(".upper", json_real(counter_max(value)));
            SUFFIX_ADD(".rate", json_real(counter_sum(value) / config->flush_interval));
        } else {
            json_object_set_new(obj, full_name, json_real(counter_sum(value)));
        }
        break;
    }
    case SET:
        json_object_set_new(obj, full_name, json_integer(set_size(value)));
        break;
    case TIMER:
    {
        timer_hist* t = (timer_hist*)value;
        /* We allow up to 40 characters for the metric name suffix. */
        const int suffix_space = 40;
        char suffixed[base_len + suffix_space];
        strcpy(suffixed, full_name);
        SUFFIX_ADD(".sum", json_real(timer_sum(&t->tm)));
        SUFFIX_ADD(".sum_sq", json_real(timer_squared_sum(&t->tm)));
        SUFFIX_ADD(".mean", json_real(timer_mean(&t->tm)));
        SUFFIX_ADD(".lower", json_real(timer_min(&t->tm)));
        SUFFIX_ADD(".upper", json_real(timer_max(&t->tm)));
        SUFFIX_ADD(".count", json_integer(timer_count(&t->tm)));
        SUFFIX_ADD(".stdev", json_real(timer_stddev(&t->tm))); /* stdev matches other output */
        for (int i = 0; i < config->num_quantiles; i++) {
            char ptile[suffix_space];
            int percentile;
            double quantile = config->quantiles[i];
            if (to_percentile(quantile, &percentile)) {
                syslog(LOG_ERR, "Invalid quantile: %lf", quantile);
                break;
            }
            snprintf(ptile, suffix_space, ".p%d", percentile);
            ptile[suffix_space-1] = '\0';
            SUFFIX_ADD(ptile, json_real(timer_query(&t->tm, quantile)));
        }
        SUFFIX_ADD(".rate", json_real(timer_sum(&t->tm) / config->flush_interval));
        SUFFIX_ADD(".sample_rate", json_real((double)timer_count(&t->tm) / config->flush_interval));

        /* Manual histogram bins */
        if (t->conf) {
            char ptile[suffix_space];
            snprintf(ptile, suffix_space, ".bin_<%0.2f", t->conf->min_val);
            ptile[suffix_space-1] = '\0';
            SUFFIX_ADD(ptile, json_integer(t->counts[0]));
            for (int i = 0; i < t->conf->num_bins - 2; i++) {
                sprintf(ptile, ".bin_%0.2f", t->conf->min_val+(t->conf->bin_width*i));
                SUFFIX_ADD(ptile, json_integer(t->counts[i+1]));
            }
            sprintf(ptile, ".bin_>%0.2f", t->conf->max_val);
            SUFFIX_ADD(ptile, json_integer(t->counts[t->conf->num_bins - 1]));
        }
        break;
    }
    default:
        syslog(LOG_ERR, "Unknown metric type: %d", type);
        break;
    }
}


/*
 * Callback function for adding a metric into json object. This function
 * is called by iterator of metrics object.
 * TODO: There is a lot redundant code here with sink_stream to normalize
 * an output representation of a metrics.
 * @arg data The config data, including configs and the output objects.
 * @arg type The type of metrics.
 * @arg metric The metirc key.
 * @arg value The metric value.
 * @return 0 on success.
 */
static int _add_metric_cb(void* data,
                          metric_type type,
                          char* metric,
                          void* value) {

    struct metric_cb_info* info = (struct metric_cb_info*)data;
    hashmap* json_map = info->json_map;
    const statsite_config* config = info->config;
    const sink_config_http* httpconfig = info->httpconfig;

    /* Extract partition info */
    char* partition;
    int name_len;
    char* pos = strchr(metric, PARTITION_DELIMITER);
    if (pos == NULL) {
        /* There is no partition data */
        partition = DEFAULT_PARTITION;
        name_len = strlen(metric);
    } else {
        /* There is partition data, separate name and partition */
        partition = pos + 1;
        name_len = pos - metric;
    }

    /* Early out if the metric name is empty */
    if (name_len == 0) {
        return 0;
    }

    /* Get prefix from config */
    char* prefix = NULL;
    uint16_t pre_len = 0;
    if (httpconfig->use_prefix) {
        prefix = config->prefixes_final[type];
        pre_len = strlen(prefix);
    }

    /*
     * Find the json object mapped to the partition string.
     * Create one if there isn't one yet.
     */
    json_t* obj = NULL;
    if (hashmap_get(json_map, partition, (void**)&obj) == -1) {
        /* Create a new json object if it doesn't exist */
        obj = json_object();
        hashmap_put(json_map, partition, obj);
    }

    assert(obj != NULL);
    _add_metric_to_json(obj, type, prefix, pre_len, metric, name_len, value, config);
    return 0;
}

/*
 * Callback function for dumping json object to string buffer.
 * @arg data The data to dump.
 * @arg size Number of bytes to dump.
 * @arg output The output string buffer.
 * @return 0 on success.
 */
static int _json_dump_cb(const char* data, size_t size, void* output) {
    strbuf* buf = (strbuf*)output;
    strbuf_cat(buf, data, size);
    return 0;
}

/*
 * Escape a string and add it to the post buffer.
 * @arg post_buf The post buffer.
 * @arg value The string to escape and append.
 * @arg len The length of the string to append. 0 if the full string should be appended.
 * @arg curl The CURL object for string escaping.
 */
static void _escape_and_append(strbuf* post_buf,
                               const char* value,
                               int len,
                               CURL* curl) {
    char* escaped_data = curl_easy_escape(curl, value, len);
    strbuf_cat(post_buf, escaped_data, strlen(escaped_data));
    curl_free(escaped_data);
}

/*
 * Verify if a key exists in a query string or not. This function simply scans
 * through the query string, hence it shouldn't be called too often.
 * @arg key The key to search. It should not contain characters '&' and '='.
 * @arg partition_string The partition string to search in.
 * @return True if the key exists as a key name(as key in key=123 but not in key123=123)
 *         in the query string, false otherwise.
 */
bool _key_exists_in_query_string(const char* key,
                                 const char* query_string) {
    if (key == NULL || query_string == NULL) {
        return false;
    }

    int key_len = strlen(key);
    int query_len = strlen(query_string);
    if (key_len == 0 || query_len == 0) {
        return false;
    }

    do {
        if (strncmp(query_string, key, key_len) == 0 &&
            (query_string[key_len] == '=' || query_string[key_len] == '&' || query_string[key_len] == '\0')) {
            return true;
        }
        query_string = strchr(query_string + 1, '&');
    } while(query_string != NULL);
    return false;
}

/*
 * Create a strbuf object and serialize a json object into it.
 * @arg obj The json object to be serialized.
 * @arg name The name of the object in the output.
 * @arg curl The helper CURL object used for escaping strings.
 * @return A buffer object if the data is not empty, NULL if it is and
 *         the further process can be skipped. Caller is responsible for
 *         freeing the buffer object.
 */
strbuf* _serialize_json_object(json_t* obj,
                               const char* name,
                               CURL* curl) {
    strbuf* json_buf;

    strbuf_new(&json_buf, 0);
    json_dump_callback(obj, _json_dump_cb, (void*)json_buf, 0);
    int json_len = 0;
    char* json_data = strbuf_get(json_buf, &json_len);
    strbuf* output = NULL;

    /* Many APIs reject empty metrics lists. We only process non-empty metrics. */
    if (json_len > 2) {
        strbuf_new(&output, json_len + INITIAL_EXTRA_POST_BUFFER_SIZE);

        strbuf_cat(output, name, strlen(name));
        strbuf_cat(output, "=", 1);
        _escape_and_append(output, json_data, json_len, curl);
    }
    
    strbuf_free(json_buf, true);
    return output;
}

/*
 * Serialize a key-value pair into strbuf as a query parameter. If the key is NULL,
 * serialize the value as a string.
 * @arg buf The output buffer.
 * @arg key The key to serialize.
 *      -- it can be NULL and in this case, '=' won't be put into the output buffer.
 * @arg value The value to serialize.
 *      -- it will be escaped if the curl parameter is not NULL,
 * @arg curl The helper CURL object used for escaping strings.
 */
void _serialize_kv(strbuf* buf, const char* key, const char* value, CURL* curl) {
    int len;

    strbuf_get(buf, &len);
    assert(value != NULL);
    if (len > 0) {
        strbuf_cat(buf, "&", 1);
    }

    if (key != NULL) {
        strbuf_cat(buf, key, strlen(key));
        strbuf_cat(buf, "=", 1);
     }

    if (curl != NULL) {
        _escape_and_append(buf, value, 0, curl);
    } else {
        strbuf_cat(buf, value, strlen(value));
    }
}

/*
 * Serialize request parameters.
 * @arg buf The output buffer.
 * @arg partition The partition string.
 * @arg value The value to serialize.
 *      -- it will be escaped if the curl parameter is not NULL,
 * @arg curl The helper CURL object used for escaping strings.
 */
void _serialize_parameters(strbuf* buf, const char* partition, const kv_config* params, CURL* curl) {
    /*
     * Dump parameters from the partition data, which is in the form of query parameters,
     * and should be escaped already.
     */
    if (partition) {
        int len = strlen(partition);
        if (len > 0) {
            _serialize_kv(buf, NULL, partition, NULL);
        }
    }

    /*
     * Encode all the free-form parameters from configuration that don't exist
     * in the partition data.
     */
    for (; params != NULL; params = params->next) {
        if (strlen(params->k) > 0 && !_key_exists_in_query_string(params->k, partition)) {
            _serialize_kv(buf, params->k, params->v, curl);
        }
    }
}

/*
 * Callback function for serializing one single json object and push into queue.
 * @arg data The callback info.
 * @arg key The key of the json object in the json map (e.g. the partition string).
 * @arg value The json object to be serialized.
 * @return 0 on success. If the callback returns 1, then the iteration stops.
 */
static int _json_serialize_cb(void* data, const char* key, void* value) {
    struct jsonmap_cb_info* info = (struct jsonmap_cb_info*)data;
    struct http_sink* sink = info->sink;
    json_t* jobject = (json_t*)value;
    CURL* curl = info->curl;

    strbuf* post_buf = _serialize_json_object(jobject, info->metrics_name, curl);

    /* Dump the time stamp */
    _serialize_kv(post_buf, info->timestamp_name, info->encoded_time, NULL);

    /* Dump other parameters */
    _serialize_parameters(post_buf, key, info->params, curl);

    /* Push the post content into queue */
    int post_len = 0;
    char* post_data = strbuf_get(post_buf, &post_len);

    int push_ret = lifoq_push(sink->queue, post_data, post_len, true, false);
    if (push_ret) {
        syslog(LOG_ERR, "HTTP Sink couldn't enqueue a %d size buffer - rejected code %d",
               post_len, push_ret);
    }

    /* Free the buffer object but keep the data */
    strbuf_free(post_buf, false);

    return 0;
}

/*
 * Delete one single json object in json map. This function is used by hashmap_iter.
 * @arg data The callback info.
 * @arg key The key of the json object in the json map (e.g. the partition string).
 * @arg value The value of the json object in the json map to be deleted.
 * @return 0 on success.
 */
static int _json_delete_cb(void* data, const char* key, void* value) {
    json_t* jobject = (json_t*)value;
    json_decref(jobject);
    return 0;
}

/*
 * Serialize metrics.
 * @arg sink The sink object to serialize metrics.
 * @arg m The metrics to be serialized.
 * @arg data The pointer to the time stamp.
 * @return 0 on success.
 */
static int _serialize_metrics(struct http_sink* sink, metrics* m, void* data) {

    /* Allocate the hashmap for json objects */
    hashmap* json_map;
    int res = hashmap_init(0, &json_map);
    if (res) return res;

    const sink_config_http* httpconfig = (const sink_config_http*)sink->sink.sink_config;

    /* Produce metrics json map from metrics.
     * For each entry in the map, the key is the query parameters and the value is
     * the json object for the metrics with the same query parameters string.
     */
    struct metric_cb_info metric_info = {
        .json_map = json_map,
        .config = sink->sink.global_config,
        .httpconfig = httpconfig
    };

    metrics_iter(m, &metric_info, _add_metric_cb);

    /* Encode the time stamp */
    CURL* curl = curl_easy_init();
    struct timeval* tv = (struct timeval*) data;
    struct tm tm;
    localtime_r(&tv->tv_sec, &tm);
    char time_buf[200];
    strftime(time_buf, 200, httpconfig->timestamp_format, &tm);
    char* encoded_time = curl_easy_escape(curl, time_buf, 0);

    /* Serialize every json object in map and push into working queue */
    struct jsonmap_cb_info jsonmap_info = {
        .metrics_name = httpconfig->metrics_name,
        .params = httpconfig->params,
        .timestamp_name = httpconfig->timestamp_name,
        .encoded_time = encoded_time,
        .curl = curl,
        .sink = sink
    };

    hashmap_iter(json_map, _json_serialize_cb, &jsonmap_info);

    /* Clean up */
    curl_free(encoded_time);
    curl_easy_cleanup(curl);

    hashmap_iter(json_map, _json_delete_cb, NULL);
    hashmap_destroy(json_map);

    return 0;
}

/*
 * libcurl data writeback handler - buffers into a growable buffer
 */
static size_t _recv_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    strbuf* buf = (strbuf*)userdata;
    /* Note: ptr is not NULL terminated, but strbuf_cat enforces a NULL */
    strbuf_cat(buf, ptr, size * nmemb);

    return size * nmemb;
}

/*
 * Attempt to check if this libcurl is using OpenSSL or NSS, which
 * differ in how ciphers are listed.
 */
static const char* _curl_which_ssl(void) {
    curl_version_info_data* v = curl_version_info(CURLVERSION_NOW);
    syslog(LOG_NOTICE, "HTTP: libcurl is built with %s %s", v->version, v->ssl_version);
    if (v->ssl_version && strncmp(v->ssl_version, "NSS", 3) == 0)
        return DEFAULT_CIPHERS_NSS;
    else
        return DEFAULT_CIPHERS_OPENSSL;
}

static void _http_curl_basic_setup(CURL* curl,
                                  const sink_config_http* httpconfig,
                                  struct curl_slist* headers,
                                  char* error_buffer,
                                  strbuf* recv_buf,
                                  const char* ssl_ciphers) {
    /* Setup HTTP parameters */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, DEFAULT_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, recv_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _recv_cb);
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, ssl_ciphers);
    if (headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USERAGENT);
}

/*
 * A helper to try to authenticate to an OAuth2 token endpoint
 */
static int _oauth2_get_token(const sink_config_http* httpconfig, struct http_sink* sink) {
    char* error_buffer = malloc(CURL_ERROR_SIZE + 1);
    strbuf* recv_buf;
    strbuf_new(&recv_buf, 16384);

    const char* ssl_ciphers;
    if (httpconfig->ciphers)
        ssl_ciphers = httpconfig->ciphers;
    else
        ssl_ciphers = _curl_which_ssl();


    CURL* curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, httpconfig->oauth_token_url);
    _http_curl_basic_setup(curl, httpconfig, NULL, error_buffer, recv_buf, ssl_ciphers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(OAUTH2_GRANT));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, OAUTH2_GRANT);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERNAME, httpconfig->oauth_key);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, httpconfig->oauth_secret);

    CURLcode rcurl = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    int recv_len;
    char* recv_data = strbuf_get(recv_buf, &recv_len);
    printf("DATA: %s\n", recv_data);
    if (http_code != 200 || rcurl != CURLE_OK) {
        syslog(LOG_ERR, "HTTP auth: error %d: %s %s", rcurl, error_buffer, recv_data);
        usleep(FAILURE_WAIT);
        goto exit;
    } else {
        json_error_t error;
        json_t* root = json_loadb(recv_data, recv_len, 0, &error);
        if (!root) {
            syslog(LOG_ERR, "HTTP auth: JSON load error: %s", error.text);
            goto exit;
        }
        char* token = NULL;
        if (json_unpack_ex(root, &error, 0, "{s:s}", "access_token", &token) != 0) {
            syslog(LOG_ERR, "HTTP auth: JSON unpack error: %s", error.text);
            json_decref(root);
            goto exit;
        }
        sink->oauth_bearer = strdup(token);
        json_decref(root);
        syslog(LOG_NOTICE, "HTTP auth: Got valid OAuth2 token");
    }

exit:

    curl_easy_cleanup(curl);
    free(error_buffer);
    strbuf_free(recv_buf, true);
    return 0;
}

/*
 * A simple background worker thread which pops from the queue and tries
 * to post. If the queue is marked closed, this thread exits
 */
static void* _http_worker(void* arg) {
    struct http_sink* s = (struct http_sink*)arg;
    const sink_config_http* httpconfig = (sink_config_http*)s->sink.sink_config;

    char* error_buffer = malloc(CURL_ERROR_SIZE + 1);
    strbuf* recv_buf;

    const char* ssl_ciphers;
    if (httpconfig->ciphers)
        ssl_ciphers = httpconfig->ciphers;
    else
        ssl_ciphers = _curl_which_ssl();

    syslog(LOG_NOTICE, "HTTP: Using cipher suite %s", ssl_ciphers);

    bool should_authenticate = httpconfig->oauth_key != NULL;

    syslog(LOG_NOTICE, "Starting HTTP worker");
    strbuf_new(&recv_buf, 16384);

    while(true) {
        void* data = NULL;
        size_t data_size = 0;
        int ret = lifoq_get(s->queue, &data, &data_size);
        if (ret == LIFOQ_CLOSED)
            goto exit;

        if (should_authenticate && s->oauth_bearer == NULL) {
            if (!_oauth2_get_token(httpconfig, s)) {
                if (lifoq_push(s->queue, data, data_size, true, true))
                    syslog(LOG_ERR, "HTTP: dropped data due to queue full of closed");
                continue;
            }
        }

        memset(error_buffer, 0, CURL_ERROR_SIZE+1);
        CURL* curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, httpconfig->post_url);

        /* Build headers */
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Connection: close");

        /* Add a bearer header if needed */
        if (should_authenticate) {
            /* 30 is header preamble + fluff */
            char bearer_header[30 + strlen(s->oauth_bearer)];
            sprintf(bearer_header, "Authorization: Bearer %s", s->oauth_bearer);
            headers = curl_slist_append(headers, bearer_header);
        }

        _http_curl_basic_setup(curl, httpconfig, headers, error_buffer, recv_buf, ssl_ciphers);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data_size);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        syslog(LOG_NOTICE, "HTTP: Sending %zd bytes to %s", data_size, httpconfig->post_url);
        /* Do it! */
        CURLcode rcurl = curl_easy_perform(curl);
        long http_code = 0;

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200 || rcurl != CURLE_OK) {

            int recv_len;
            char* recv_data = strbuf_get(recv_buf, &recv_len);

            syslog(LOG_ERR, "HTTP: error %d: %s %s", rcurl, error_buffer, recv_data);
            /* Re-enqueue data */
            if (lifoq_push(s->queue, data, data_size, true, true))
                syslog(LOG_ERR, "HTTP: dropped data due to queue full of closed");

            /* Remove any authentication token - this will cause us to get a new one */
            if (s->oauth_bearer) {
                free(s->oauth_bearer);
                s->oauth_bearer = NULL;
            }

            usleep(FAILURE_WAIT);
        } else {
            syslog(LOG_NOTICE, "HTTP: success");
            free(data);
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        strbuf_truncate(recv_buf);
    }
exit:

    free(error_buffer);
    strbuf_free(recv_buf, true);
    return NULL;
}

static void _close_sink(struct http_sink* s) {
    lifoq_close(s->queue);
    void* retval;
    pthread_join(s->worker, &retval);
    syslog(LOG_NOTICE, "HTTP: sink closed down with status %ld", (intptr_t)retval);
    return;
}

sink* init_http_sink(const sink_config_http* sc, const statsite_config* config) {
    struct http_sink* s = calloc(1, sizeof(struct http_sink));
    s->sink.sink_config = (const sink_config*)sc;
    s->sink.global_config = config;
    s->sink.command = (int (*)(sink*, metrics*, void*))_serialize_metrics;
    s->sink.close = (void (*)(sink*))_close_sink;

    lifoq_new(&s->queue, QUEUE_MAX_SIZE);
    pthread_create(&s->worker, NULL, _http_worker, (void*)s);

    return (sink*)s;
}
