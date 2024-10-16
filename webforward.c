#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <locale.h>
#include <json-c/json.h>
#include <iconv.h>
#include <regex.h>




#define CONFIG_FILE "/home/root/r200/ipv6_forward.config"
#define PUSH_TYPE_PREFIX "push_type:"
#define PUSHPLUS_API "https://www.pushplus.plus/send"
#define USERNAME_PREFIX "username:"
#define PASSWORD_PREFIX "password:"
#define TOKEN_PREFIX "token:"
#define DINGTALK_PREFIX "dingtalk:"
#define SECRET_PREFIX "secret:"
#define WXPUSH_PREFIX "wxpush:"
#define WXPUSH_UIDS "wxpush_uids:"
#define BARK_PREFIX "bark_key:"
#define GOTIFY_TOKEN "gotify_token:"
#define GOTIFY_URL "gotify_url:"
#define MAX_TOKEN_LENGTH 64
#define MAX_IPv6_LENGTH 40
#define UPTIME_FILE "/proc/uptime"
#define MAX_QUERY_LENGTH 256
#define MAX_CONTENT_LENGTH 1024
#define MAX_IDX_LENGTH 256
#define TEMP_THRESHOLD 75000 // 50度，单位为0.01度
#define SMS_THRESHOLD 50 // 定义短信容量阈值，用于自动删除短信

char webs_session[256] = {0}; // 全局变量存储 -webs-session- 值

//日志函数
void log_with_timestamp(const char *message) {
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("%s %s\n", timestamp, message);

    struct stat st;
    if (stat("/home/root/r200/forward.log", &st) == 0 && st.st_size > 1024 * 1024) { // 当文件大小大于1MB
        FILE *file = fopen("/home/root/r200/forward.log", "w"); // 进行覆写文件
        if (file != NULL) {
            fprintf(file, "%s %s\n", timestamp, message);
            fprintf(file, "\n"); // 添加换行符
            fclose(file);
        } else {
            printf("无法打开日志文件进行写入\n");
        }
    } else {
        FILE *file = fopen("/home/root/r200/forward.log", "a");
        if (file != NULL) {
            fprintf(file, "%s %s\n", timestamp, message);
            fprintf(file, "\n"); // 添加换行符
            fclose(file);
        } else {
            printf("无法打开日志文件进行写入\n");
        }
    }
}

//用户选择函数
void get_config_from_user(char *username,char *password,char *token, char *dingtalk, char *secret, char *push_type, char *wxpush_appToken, char *wxpush_uids, char *bark_key, char *gotify_token, char *gotify_url) {
	log_with_timestamp("请选择输入用户名:");
    scanf("%35s", username);
    log_with_timestamp("请输入密码:");
    scanf("%35s", password);
    log_with_timestamp("请选择推送方式（1：PushPlus，2：钉钉，3：WxPusher, 4:bark, 5:gotify）:");
    scanf("%1s", push_type);
    if (strcmp(push_type, "1") == 0) {
        log_with_timestamp("请输入pushplus的token:");
        scanf("%32s", token);
    } else if (strcmp(push_type, "2") == 0) {
        log_with_timestamp("请输入钉钉机器人的token:");
        scanf("%64s", dingtalk);
        log_with_timestamp("请输入钉钉机器人的secret:");
        scanf("%67s", secret);
    } else if (strcmp(push_type, "3") == 0) {
        log_with_timestamp("请输入WxPusher的appToken:");
        scanf("%35s", wxpush_appToken);
        log_with_timestamp("请输入WxPusher的uids:");
        scanf("%32s", wxpush_uids);
    } else if (strcmp(push_type, "4") == 0) {
        log_with_timestamp("请输入bark的bark_key:");
        scanf("%35s", bark_key);
    } else if (strcmp(push_type, "5") == 0) {
        log_with_timestamp("请输入gotify的gotify_token:");
        scanf("%35s", gotify_token);
        log_with_timestamp("请输入gotify的gotify_url:");
        scanf("%35s", gotify_url);
    } 
}

//实现push推送函数
void send_pushplus_notification(const char *token, const char *title, const char *content) {
    char command[512];
   sprintf(command, "curl -X POST http://www.pushplus.plus/send/ -H \"Content-Type: application/json\" -d '{\"token\":\"%s\", \"title\":\"%s\", \"content\":\"%s\"}'", token, title, content);
    
    log_with_timestamp(command); // 记录命令内容

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("无法执行命令");
        return;
    }
    char response[256];
    while (fgets(response, sizeof(response), fp) != NULL) {
        log_with_timestamp(response); // 记录响应内容
    }
    pclose(fp);
}

//钉钉机器人安全设置：加签
char *base64(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    return buff;
}


//实现钉钉机器人推送
void send_dingtalk_notification(const char *dingtalk, const char *secret, const char *content) {
    setlocale(LC_ALL, "en_US.UTF-8");  //设置字符编码为UTF-8
    long long timestamp = (long long)time(NULL) * 1000;
    char string_to_sign[256];
    sprintf(string_to_sign, "%lld\n%s", timestamp, secret);
    unsigned char* digest = HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)string_to_sign, strlen(string_to_sign), NULL, NULL);    
    char* base64_encoded = base64(digest, EVP_MD_size(EVP_sha256()));
    char* url_encoded_sign = curl_easy_escape(NULL, base64_encoded, 0);
    char url[1024];
    sprintf(url, "https://oapi.dingtalk.com/robot/send?access_token=%s&timestamp=%lld&sign=%s", dingtalk, timestamp, url_encoded_sign);
    char post_data[1024];
    sprintf(post_data, "{\"msgtype\": \"text\", \"text\": {\"content\": \"%s\"}, \"at\": {\"isAtAll\": true}}", content);

    //log_with_timestamp(url); // 记录命令内容
    log_with_timestamp(post_data); // 记录响应内容

    CURL *curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_slist_free_all(headers); // 释放头列表
        curl_easy_cleanup(curl);
    }
}

//实现bark推送
void send_bark_notification(const char *bark_key, const char *title, const char *content) {
    // 使用 json-c 库自动转义 JSON 字符串
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "title", json_object_new_string(title));
    json_object_object_add(jobj, "body", json_object_new_string(content));
    json_object_object_add(jobj, "device_key", json_object_new_string(bark_key));
    const char *json_str = json_object_to_json_string(jobj);

    char command[512];
    snprintf(command, sizeof(command), "curl -s -H \"Content-Type: application/json; charset=utf-8\" -X POST -d '%s' \"https://api.day.app/push\"", json_str);
    
    log_with_timestamp(command); // 记录命令内容

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("无法执行命令");
        json_object_put(jobj);
        return;
    }
    char response[256];
    while (fgets(response, sizeof(response), fp) != NULL) {
        log_with_timestamp(response); // 记录响应内容
    }
    pclose(fp);
    json_object_put(jobj);
}

//实现gotify推送
void send_gotify_notification(const char *gotify_url, const char *gotify_token, const char *title, const char *content) {
    char command[512];
    snprintf(command, sizeof(command), "curl -s \"%s/message?token=%s\" -F \"title=%s\" -F \"message=%s\" -F \"priority=5\"", gotify_url, gotify_token, title, content);
    
    log_with_timestamp(command); // 记录命令内容

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("无法执行命令");
        return;
    }
    char response[256];
    while (fgets(response, sizeof(response), fp) != NULL) {
        log_with_timestamp(response); // 记录响应内容
    }
    pclose(fp);
}

//实现wxpush推送函数
void send_wxpush_notification(const char *appToken, const char *uids, const char *title, const char *content) {
    // 使用 json-c 库自动转义 JSON 字符串
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "appToken", json_object_new_string(appToken));
    // 将 uids 转换为 JSON 数组
    struct json_object *jarray = json_object_new_array();
    json_object_array_add(jarray, json_object_new_string(uids));
    json_object_object_add(jobj, "uids", jarray);
    json_object_object_add(jobj, "content", json_object_new_string(content));
    json_object_object_add(jobj, "summary", json_object_new_string(title));
    const char *json_str = json_object_to_json_string(jobj);
    char escaped_json_str[1024]; // 增加缓冲区大小
    strcpy(escaped_json_str, json_str);
    for (char *p = escaped_json_str; *p; p++) {
        if (*p == '\'') {
            *p = '\"';
        }
    }

    char command[512]; 
    snprintf(command, sizeof(command), "curl -s -H \"Content-Type: application/json\" -X POST -d '%s' http://wxpusher.zjiecode.com/api/send/message", escaped_json_str);

    log_with_timestamp(command); // 记录命令内容

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("无法执行命令");
        json_object_put(jobj);
        return;
    }
    char response[256];
    while (fgets(response, sizeof(response), fp) != NULL) {
        log_with_timestamp(response); // 记录响应内容
    }
    pclose(fp);
    json_object_put(jobj);
}

// 隐私加密函数
void mask_phone_number(char *text) {
    regex_t regex;
    regmatch_t pmatch[1];
    const char *pattern = "\\b[0-9]{11}\\b";
    char masked_number[15];
    int offset = 0;

    // 编译正则表达式
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        fprintf(stderr, "无法编译正则表达式\n");
        return;
    }

    // 查找并替换手机号码
    while (regexec(&regex, text + offset, 1, pmatch, 0) == 0) {
        int start = pmatch[0].rm_so + offset;
        int end = pmatch[0].rm_eo + offset;
        
        // 确认匹配的数字长度是11位
        if (end - start == 11) {
            snprintf(masked_number, sizeof(masked_number), "%.3s*****%.3s", text + start, text + end - 3);
            // 将匹配到的号码替换为掩码后的号码
            memmove(text + start, masked_number, 11);
        }

        // 更新偏移量
        offset = end;
    }

    // 释放正则表达式
    regfree(&regex);
}


// HMACMD5加密函数，用于处理用户登录的加密
void hmac_md5(const char *key, const char *data, unsigned char *result) {
    unsigned int len = 16;
    HMAC(EVP_md5(), key, strlen(key), (unsigned char *)data, strlen(data), result, &len);
}
size_t writefunc(void *ptr, size_t size, size_t nmemb, char *s) {
    size_t new_len = strlen(s) + size * nmemb;
    if (new_len >= 5120) { // 确保新长度不会溢出缓冲区
        fprintf(stderr, "Response buffer is too small.\n");
        return 0; // 停止写入，避免溢出
    }
    strncat(s, ptr, size * nmemb);
    return size * nmemb;
}
size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    char *start = strstr(buffer, "Set-Cookie: ");
    if (start) {
        start += strlen("Set-Cookie: ");
        char *end = strchr(start, '\r');
        if (!end) {
            end = strchr(start, '\n');
        }
        if (end) {
            snprintf(webs_session, end - start + 1, "%.*s", (int)(end - start), start);
            
            char log_message[512];  // 创建一个缓冲区来格式化字符串
            snprintf(log_message, sizeof(log_message), "cookie=%s", webs_session);
            
            log_with_timestamp(log_message);  // 传递格式化后的字符串
        }
    }
    return nitems * size;
}
void to_hex_string(unsigned char *hash, char *hex_string, int len) {
    for (int i = 0; i < len; i++) sprintf(hex_string + (i * 2), "%02x", hash[i]);
    hex_string[len * 2] = '\0';
}

//登录函数，用于获取ck
void login(const char *url, const char *key, const char *username, const char *password) {
    CURL *curl = curl_easy_init();
    if (curl) {
        unsigned char hash[16];
        char hmac_username[33], hmac_password[33], json[200], response[1000] = {0};
        struct curl_slist *headers = NULL;
       
        hmac_md5(key, username, hash);
        to_hex_string(hash, hmac_username, 16);
        hmac_md5(key, password, hash);
        to_hex_string(hash, hmac_password, 16);

        snprintf(json, sizeof(json), "{\"username\": \"%s\", \"password\": \"%s\"}", hmac_username, hmac_password);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK && strstr(response, "\"retcode\":0")) {
            log_with_timestamp("Login successful\n");
        } else {
            log_with_timestamp("Login failed\n");
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    } else {
        printf("CURL initialization failed!\n");
    }
    curl_global_cleanup();
}

// 设置未读短信为已读
void read_sms_info(const char *sms_id, int smsbox) {
    CURL *curl = curl_easy_init();
    if (curl) {
        const char *url = "http://localhost/action/sms_read_sms_info";
        char post_data[256];
        snprintf(post_data, sizeof(post_data), "{\"index\": \"%s\", \"smsbox\": %d}", sms_id, smsbox);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        // 添加必要的cookie header
        char cookie_header[512];
        snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", webs_session);
        headers = curl_slist_append(headers, cookie_header);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);

        char response[5120] = {0};
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        // 打印请求数据
        //printf("Request: %s\n", post_data);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to read SMS info: %s\n", curl_easy_strerror(res));
        } else {
            // 打印响应数据
            //printf("Response: %s\n", response);

            // 解析响应JSON
            struct json_object *parsed_json = json_tokener_parse(response);
            struct json_object *retcode_obj;
            json_object_object_get_ex(parsed_json, "retcode", &retcode_obj);
            int retcode = json_object_get_int(retcode_obj);

            if (retcode == 0) {
                printf("\n短信已设置成已读\n");
            } else {
                printf("Failed to set SMS as read\n");
            }

            json_object_put(parsed_json); // 释放JSON对象
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
}

//自动删除短信函数
void delete_sms(const char *sms_id, int smsbox) {
    CURL *curl = curl_easy_init();
    if (curl) {
        const char *url = "http://localhost/action/sms_del_sms_info";
        char post_data[256];
        snprintf(post_data, sizeof(post_data), "{\"index\": [\"%s\"], \"smsbox\": %d}", sms_id, smsbox);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        // 添加必要的cookie header
        char cookie_header[512];
        snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", webs_session);
        headers = curl_slist_append(headers, cookie_header);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);

        char response[5120] = {0};
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        // 打印请求数据
        //printf("Request: %s\n", post_data);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to delete SMS: %s\n", curl_easy_strerror(res));
        } else {
            // 打印响应数据
            //printf("Response: %s\n", response);

            // 解析响应JSON
            struct json_object *parsed_json = json_tokener_parse(response);
            struct json_object *retcode_obj;
            json_object_object_get_ex(parsed_json, "retcode", &retcode_obj);
            int retcode = json_object_get_int(retcode_obj);

            if (retcode == 0) {
                printf("短信已删除\n");
            } else {
                printf("Failed to delete SMS\n");
            }

            json_object_put(parsed_json); // 释放JSON对象
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
}

// 获取短信列表并推送未读短信的函数
void get_sms_list(const char *push_type, const char *token, const char *dingtalk, const char *secret, const char *wxpush_appToken, const char *wxpush_uids, const char *bark_key, const char *gotify_url, const char *gotify_token, int smsbox) {
    CURL *curl = curl_easy_init();
    if (curl) {
        const char *url = "http://localhost/action/sms_get_sms_list";
        const char *json_body = "{\"start\": 1, \"end\": 100, \"smsbox\": 1}";
        char response[5120] = {0}; // 增加缓冲区大小
        
        struct curl_slist *headers = NULL;
        char cookie_header[512];
        snprintf(cookie_header, sizeof(cookie_header), "Cookie: %s", webs_session);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, cookie_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            // 解析响应并提取信息
            struct json_object *parsed_json, *data, *smsList, *sms;
            parsed_json = json_tokener_parse(response);
            json_object_object_get_ex(parsed_json, "data", &data);
            json_object_object_get_ex(data, "smsList", &smsList);
            int totalCount = json_object_get_int(json_object_object_get(data, "totalCount"));

            if (totalCount >= SMS_THRESHOLD) {
                // 找到时间最早的一条短信
                time_t earliest_time = LONG_MAX;
                const char *earliest_sms_id = NULL;
                
                for (int i = 0; i < json_object_array_length(smsList); i++) {
                    sms = json_object_array_get_idx(smsList, i);
                    time_t sms_time = (time_t)json_object_get_int(json_object_object_get(sms, "datetime"));
                    if (sms_time < earliest_time) {
                        earliest_time = sms_time;
                        earliest_sms_id = json_object_get_string(json_object_object_get(sms, "index"));
                    }
                }

                if (earliest_sms_id) {
                    delete_sms(earliest_sms_id, smsbox); // 删除最早的一条短信
                }
            }

            for (int i = 0; i < json_object_array_length(smsList); i++) {
                sms = json_object_array_get_idx(smsList, i);

                int isread = json_object_get_int(json_object_object_get(sms, "isread"));
                if (isread == 0) { // 仅处理未读短信
                    const char *phone = json_object_get_string(json_object_object_get(sms, "phone"));//获取短信号码
                    const char *content = json_object_get_string(json_object_object_get(sms, "content"));//获取短信内容
                    const char *sms_id = json_object_get_string(json_object_object_get(sms, "index")); // 获取短信ID

                    // 格式化日期时间
                    char datetime_str[100];
                    time_t dt = (time_t)json_object_get_int(json_object_object_get(sms, "datetime"));//获取短信时间戳
                    struct tm *tm_info = localtime(&dt);
                    strftime(datetime_str, sizeof(datetime_str), "%Y-%m-%d %H:%M:%S", tm_info);

                    // 格式化电话
                    char formatted_phone[256];
                    strcpy(formatted_phone, phone);
                    mask_phone_number(formatted_phone);

                    // 输出信息
                    //printf("\n发件人: %s\n时间: %s\n*********************************\n短信内容: \n%s\n\n", formatted_phone, datetime_str, content);

                    // 推送未读短信
                    char push_content[5120];
                    snprintf(push_content, sizeof(push_content), "\n新短信\n发件人: %s\n时间: %s\n*********************************\n短信内容: \n%s\n", formatted_phone, datetime_str, content);
                    log_with_timestamp(push_content);

                    if (strcmp(push_type, "1") == 0) {
                        send_pushplus_notification(token, "短信通知", push_content);
                    } else if (strcmp(push_type, "2") == 0) {
                        send_dingtalk_notification(dingtalk, secret, push_content);
                    } else if (strcmp(push_type, "3") == 0) {
                        send_wxpush_notification(wxpush_appToken, wxpush_uids, "短信通知", push_content);
                    } else if (strcmp(push_type, "4") == 0) {
                        log_with_timestamp("正在进行Bark推送...");
                        send_bark_notification(bark_key, "短信通知", push_content);
                    } else if (strcmp(push_type, "5") == 0) {
                        log_with_timestamp("正在进行gotify推送...");
                        send_gotify_notification(gotify_url, gotify_token, "短信通知", push_content);
                    }

                    // 模拟点击查看短信
                    read_sms_info(sms_id, smsbox); // 调用模拟查看短信的函数
                }
            }

            json_object_put(parsed_json);
        } else {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
}


// 获取CPE温度
void check_temperature(const char *token, const char *dingtalk, const char *secret, const char *push_type, const char *wxpush_appToken, const char *wxpush_uids, const char *bark_key, const char *gotify_url, const char *gotify_token) {
    FILE *fp;
    char buffer[1024];
    fp = popen("curl -s http://localhost:12315/api/temp", "r");
    if (fp == NULL) {
        perror("无法运行命令");
        return;
    }
    fread(buffer, 1, sizeof(buffer) - 1, fp);
    pclose(fp);

    struct json_object *parsed_json;
    struct json_object *data;
    struct json_object *temp1;

    parsed_json = json_tokener_parse(buffer);
    json_object_object_get_ex(parsed_json, "data", &data);
    json_object_object_get_ex(data, "temp1", &temp1);

    int temperature1 = json_object_get_int(temp1);
    float temp_in_celsius = temperature1 / 1000.0;
    
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "\n您的CPE当前温度为: %.1f度\n", temp_in_celsius);
    log_with_timestamp(log_message); // 记录当前温度

    if (temperature1 > TEMP_THRESHOLD) {
        char content[256];
        sprintf(content, "您的CPE当前温度为: %.1f度, 要爆炸啦! \n此温度为芯片内部温度，非主板和设备温度，设备实际温度会低于此温度！\n作者QQ:2353223717", temp_in_celsius);
        log_with_timestamp(content); // 记录警告内容

        if (strcmp(push_type, "1") == 0) {
            send_pushplus_notification(token, "CPE温度异常", content);
        } else if (strcmp(push_type, "2") == 0) {
            send_dingtalk_notification(dingtalk, secret, content);
        } else if (strcmp(push_type, "3") == 0) {
            send_wxpush_notification(wxpush_appToken, wxpush_uids, "CPE温度异常", content);
        } else if (strcmp(push_type, "4") == 0) {
            send_bark_notification(bark_key, "CPE温度异常", content);
        } else if (strcmp(push_type, "5") == 0) {
            send_gotify_notification(gotify_url, gotify_token, "CPE温度异常", content);
        }
    }

    json_object_put(parsed_json);
}

//获取系统运行时间并处理格式
void get_system_uptime(int *uptime_days, int *uptime_hours, int *uptime_minutes, int *uptime_seconds) {
    FILE *file;
    double uptime_seconds_double;
    int uptime_seconds_int;
    file = fopen("/proc/uptime", "r");
    if (file == NULL) {
        perror("无法打开 /proc/uptime 文件");
        return;
    }
    fscanf(file, "%lf", &uptime_seconds_double);
    fclose(file);
    uptime_seconds_int = (int)uptime_seconds_double;
    *uptime_days = uptime_seconds_int / (3600 * 24);
    uptime_seconds_int = uptime_seconds_int % (3600 * 24);
    *uptime_hours = uptime_seconds_int / 3600;
    uptime_seconds_int = uptime_seconds_int % 3600;
    *uptime_minutes = uptime_seconds_int / 60;
    *uptime_seconds = uptime_seconds_int % 60;
}

//获取IPv6地址
void get_ipv6_address(char *ipv6, int first_time, const char *token, const char *dingtalk, const char *secret, const char *push_type, const char *wxpush_appToken, const char *wxpush_uids, const char *bark_key, const char *gotify_url, const char *gotify_token) {
    FILE *fp;
    char line[256];
    char new_ipv6[MAX_IPv6_LENGTH + 1] = {0};
    int uptime_days, uptime_hours, uptime_minutes, uptime_seconds;   
    fp = popen("ip -6 addr show", "r");
    if (fp == NULL) {
        perror("无法运行命令");
        return;
    }
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "inet6") && strstr(line, "scope global")) {
            sscanf(line, " inet6 %39[^/]", new_ipv6);
            break;
        }
    }
    pclose(fp);
    if (strcmp(ipv6, new_ipv6) != 0) {
        strcpy(ipv6, new_ipv6);
        char message[256];
        if (first_time) {
            sprintf(message, "已成功获取本机IPv6地址:%s", ipv6);
            log_with_timestamp(message);
        } else {
            get_system_uptime(&uptime_days, &uptime_hours, &uptime_minutes, &uptime_seconds);
            sprintf(message, "IPv6地址已更新,新地址为:%s", ipv6);
            log_with_timestamp(message);
            char content[512];
            sprintf(content, "IPv6地址已更新,新地址为%s\n系统已运行:%d天%d小时%d分钟%d秒", ipv6, uptime_days, uptime_hours, uptime_minutes, uptime_seconds);
                        if (strcmp(push_type, "1") == 0) {
                send_pushplus_notification(token, "IPv6地址更新", content);
            } else if (strcmp(push_type, "2") == 0) {
                send_dingtalk_notification(dingtalk, secret, content);
            } else if (strcmp(push_type, "3") == 0) {
                send_wxpush_notification(wxpush_appToken, wxpush_uids, "IPv6地址更新", content);
            } else if (strcmp(push_type, "4") == 0) {
                send_bark_notification(bark_key,"IPv6地址更新", content);
            } else if (strcmp(push_type, "5") == 0) {
                send_gotify_notification(gotify_url, gotify_token, "IPv6地址更新", content);
                }
        }
    }
}

//判断设备是否重启
void send_system_uptime_notification(const char *token, const char *dingtalk, const char *secret, const char *push_type, const char *wxpush_appToken, const char *wxpush_uids, int *notified, const char *bark_key, const char *gotify_url, const char *gotify_token) {    
    int uptime_days, uptime_hours, uptime_minutes, uptime_seconds;
    char message[256];
    get_system_uptime(&uptime_days, &uptime_hours, &uptime_minutes, &uptime_seconds);
    if ((uptime_days == 0 && uptime_hours == 0 && uptime_minutes < 3) && !*notified) {
        sprintf(message, "您尊贵的CPE于%d分钟%d秒前重启了", uptime_minutes, uptime_seconds);
        log_with_timestamp(message);
        char content[256];
        sprintf(content, "您尊贵的CPE于%d分钟%d秒前重启了\n系统已运行:%d天%d小时%d分钟%d秒", uptime_minutes, uptime_seconds, uptime_days, uptime_hours, uptime_minutes, uptime_seconds);
        if (strcmp(push_type, "1") == 0) {
            send_pushplus_notification(token, "系统重启", content);
        } else if (strcmp(push_type, "2") == 0) {
            send_dingtalk_notification(dingtalk, secret, content);
        } else if (strcmp(push_type, "3") == 0) {
            send_wxpush_notification(wxpush_appToken, wxpush_uids, "系统重启", content);
        } else if (strcmp(push_type, "3") == 0) {
            send_wxpush_notification(wxpush_appToken, wxpush_uids, "系统重启", content);
        } else if (strcmp(push_type, "4") == 0) {
            send_bark_notification(bark_key, "系统重启", content);
        } else if (strcmp(push_type, "5") == 0) {
            send_gotify_notification(gotify_url, gotify_token, "系统重启", content);
                }
        *notified = 1;  // 标记为已发送通知但未打印时间        
    } else if ((uptime_days != 0 || uptime_hours != 0 || uptime_minutes >= 3) && *notified != 2) {         
        sprintf(message, "系统已运行:%d天%d小时%d分钟%d秒", uptime_days, uptime_hours, uptime_minutes, uptime_seconds);
        *notified = 2;
        log_with_timestamp(message);
    }
}

//添加自启到系统服务
void create_and_start_service() {
    FILE *file;
    file = fopen("/lib/systemd/system/forward.service", "w");
    if (file == NULL) {
        perror("无法打开服务文件进行写入");
        return;
    }
    fprintf(file, "[Unit]\nDescription=forward Service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=forward >> /home/root/r200/forward.log 2>&1\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n");
    fclose(file);
    if (system("systemctl daemon-reload") == -1) {
        perror("无法重新加载systemd的配置");
        return;
    }
    if (system("systemctl enable forward.service") == -1) {
        perror("无法设置服务在启动时自动运行");
        return;
    }
    log_with_timestamp("服务已成功创建");
    log_with_timestamp("请手动停止该会话(Ctrl+C),并手动执行:\nsystemctl start forward.service");
}

int main() {
    FILE *file;
    char line[256];
    char username[MAX_TOKEN_LENGTH + 1] = {0};
    char password[MAX_TOKEN_LENGTH + 1] = {0};
    char token[MAX_TOKEN_LENGTH + 1] = {0};
    char dingtalk[MAX_TOKEN_LENGTH + 1] = {0};
    char secret[MAX_TOKEN_LENGTH + 1] = {0};
    char push_type[MAX_TOKEN_LENGTH + 1] = {0};
    char wxpush_appToken[MAX_TOKEN_LENGTH + 1] = {0};
    char wxpush_uids[MAX_TOKEN_LENGTH + 1] = {0};
    char bark_key[MAX_TOKEN_LENGTH + 1] = {0};
    char gotify_token[MAX_TOKEN_LENGTH + 1] = {0};
    char gotify_url[MAX_TOKEN_LENGTH + 1] = {0};
    char ipv6[MAX_IPv6_LENGTH + 1] = {0};
    int username_found = 0;
    int password_found = 0; 
    int token_found = 0;
    int dingtalk_found = 0;
    int secret_found = 0;
    int push_type_found = 0;
    int wxpush_found = 0;
    int wxpush_uids_found = 0;
    int bark_key_found = 0;
    int gotify_token_found = 0;
    int gotify_url_found = 0;
    char content[MAX_CONTENT_LENGTH] = {0};
    char idx[MAX_IDX_LENGTH] = {0};
    int temperature_counter = 0;
    int login_counter = 0;
    int g_smsType = 1; // 1是收件箱类型
   
    
    
   
   // 检查数据库文件位置
   const char *db_path =NULL;
    if (access("/m_data/usr/dbm/database.db", F_OK) == 0) {
        db_path = "/m_data/usr/dbm/database.db";
    } else if (access("/usrdata/usr/dbm/database.db", F_OK) == 0) {
        db_path = "/usrdata/usr/dbm/database.db";
    } else {
        fprintf(stderr, "无法找到数据库文件\n");
        return 1;
    }
    
    
    file = fopen(CONFIG_FILE, "r");
    if (file != NULL) {
        while (fgets(line, sizeof(line), file)) {
        	  if (strncmp(line, USERNAME_PREFIX, strlen(USERNAME_PREFIX)) == 0) {
                sscanf(line, "username:%s", username);
                username_found = 1;
            } else if (strncmp(line, PASSWORD_PREFIX, strlen(PASSWORD_PREFIX)) == 0) {
                sscanf(line, "password:%s", password);
                password_found = 1;
            } else if (strncmp(line, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) == 0) {
                sscanf(line, "token:%s", token);
                token_found = 1;
            } else if (strncmp(line, DINGTALK_PREFIX, strlen(DINGTALK_PREFIX)) == 0) {
                sscanf(line, "dingtalk:%s", dingtalk);
                dingtalk_found = 1;
            } else if (strncmp(line, SECRET_PREFIX, strlen(SECRET_PREFIX)) == 0) {
                sscanf(line, "secret:%s", secret);
                secret_found = 1;
            } else if (strncmp(line, PUSH_TYPE_PREFIX, strlen(PUSH_TYPE_PREFIX)) == 0) {
                sscanf(line, "push_type:%s", push_type);
                push_type_found = 1;
            } else if (strncmp(line, WXPUSH_PREFIX, strlen(WXPUSH_PREFIX)) == 0) {
                sscanf(line, "wxpush:%s", wxpush_appToken);
                wxpush_found = 1;
            } else if (strncmp(line, WXPUSH_UIDS, strlen(WXPUSH_UIDS)) == 0) {
                sscanf(line, "wxpush_uids:%s", wxpush_uids);
                wxpush_uids_found = 1;
            } else if (strncmp(line, BARK_PREFIX,strlen(BARK_PREFIX)) == 0) {
                sscanf(line, "bark_key:%s", bark_key);
                bark_key_found = 1;
            } else if (strncmp(line, GOTIFY_TOKEN,strlen(GOTIFY_TOKEN)) == 0) {
                sscanf(line, "gotify_token:%s", gotify_token);
                gotify_token_found = 1;
            } else if (strncmp(line, GOTIFY_URL,strlen(GOTIFY_URL)) == 0) {
                sscanf(line, "gotify_url:%s", gotify_url);
                gotify_url_found = 1;
            }
        }
        fclose(file);
    } 
    
    //检查是否存在配置文件
    if (push_type_found) {
    		log_with_timestamp("检测到配置文件...");
                if (!username_found || !password_found ) {
                	log_with_timestamp("未检测到用户配置...");
                    log_with_timestamp("请在下面输入用户名:\n");
                    scanf("%35s", username);
                    log_with_timestamp("请输入密码:\n");
        			 scanf("%32s", password);
                    file = fopen(CONFIG_FILE, "a");
                    if (file == NULL) {
                        perror("无法打开配置文件进行写入");
                        return 1;
                    }
                    fprintf(file, "#用户配置\n");
                    fprintf(file, "%s%s\n", USERNAME_PREFIX, username);
                    fprintf(file, "%s%s\n", PASSWORD_PREFIX,  password);
                    fclose(file);
                    log_with_timestamp("用户配置已写入配置文件");
                }
        if (strcmp(push_type, "1") == 0 || strcmp(push_type, "2") == 0 || strcmp(push_type, "3") == 0 || strcmp(push_type, "4") == 0 || strcmp(push_type, "5") == 0) {
            if (strcmp(push_type, "1") == 0) {
                log_with_timestamp("检测到已选择 PushPlus 推送...");
                if (!token_found) {
                	log_with_timestamp("未检测到 PushPlus 配置...");
                    log_with_timestamp("请在下面输入 pushplus 的 token:");
                    scanf("%32s", token);
                    file = fopen(CONFIG_FILE, "a");
                    if (file == NULL) {
                        perror("无法打开配置文件进行写入");
                        return 1;
                    }
                    fprintf(file, "#pushplus配置\n");
                    fprintf(file, "%s%s\n", TOKEN_PREFIX, token);
                    fclose(file);
                    log_with_timestamp("pushplus 的 token 已写入配置文件");
                }
            } else if (strcmp(push_type, "2") == 0) {
                log_with_timestamp("检测到已选择 钉钉推送...");
                if (!dingtalk_found || !secret_found) {
                	log_with_timestamp("未检测到 钉钉机器人 配置...");
                    log_with_timestamp("请在下面输入钉钉机器人推送的token:\n");
                    scanf("%64s", dingtalk);
                    log_with_timestamp("请在下面输入钉钉机器人推送的secret:\n");
                    scanf("%67s", secret);
                    file = fopen(CONFIG_FILE, "a");
                    if (file == NULL) {
                        perror("无法打开配置文件进行写入");
                        return 1;
                    }
                    fprintf(file, "#钉钉机器人配置\n");
                    fprintf(file, "%s%s\n", DINGTALK_PREFIX, dingtalk);
                    fprintf(file, "%s%s\n", SECRET_PREFIX, secret);
                    fclose(file);
                    log_with_timestamp("钉钉机器人的 token 和 secret 已写入配置文件");
                }
            } else if (strcmp(push_type, "3") == 0) {
                log_with_timestamp("检测到已选择 WxPusher 推送...\n");
                if (!wxpush_found) {
                	log_with_timestamp("未检测到 WxPusher 配置...");
                    log_with_timestamp("请在下面输入 WxPusher 的 appToken:\n");
                    scanf("%35s", wxpush_appToken);
                    log_with_timestamp("请输入WxPusher的uids:");
        			 scanf("%32s", wxpush_uids);
                    file = fopen(CONFIG_FILE, "a");
                    if (file == NULL) {
                        perror("无法打开配置文件进行写入");
                        return 1;
                    }
                    fprintf(file, "#Wxpush配置\n");
                    fprintf(file, "%s%s\n", WXPUSH_PREFIX, wxpush_appToken);
                    fprintf(file, "%s%s\n", WXPUSH_UIDS,  wxpush_uids);
                    fclose(file);
                    log_with_timestamp("WxPusher 的 appToken, Uid 已写入配置文件");
                }
            } else if (strcmp(push_type, "4") == 0) { 
                log_with_timestamp("检测到已选择 Bark 推送...");
                if (!bark_key_found) {
                    log_with_timestamp("未检测到 Bark 配置...");
                    log_with_timestamp("请在下面输入 Bark 的 key:");
                    scanf("%32s", bark_key);
                    file = fopen(CONFIG_FILE, "a");
                    if (file == NULL) {
                        perror("无法打开配置文件进行写入");
                        return 1;
                    }
                    fprintf(file, "#Bark配置\n");
                    fprintf(file, "bark_key:%s\n", bark_key);
                    fclose(file);
                    log_with_timestamp("Bark 的 key 已写入配置文件");
                }
            } else if (strcmp(push_type, "5") == 0) { 
                log_with_timestamp("检测到已选择 gotify推送...");
                if (!gotify_token_found) {
                    log_with_timestamp("未检测到 gotify 配置...");
                    log_with_timestamp("请在下面输入 gotify的 token:");
                    scanf("%32s", gotify_token);
                    log_with_timestamp("请输入 gotify的 url:");
                    scanf("%32s", gotify_url);
                    file = fopen(CONFIG_FILE, "a");
                    if (file == NULL) {
                        perror("无法打开配置文件进行写入");
                        return 1;
                    }
                    fprintf(file, "#gotify配置\n");
                    fprintf(file, "gotify_token:%s\n", gotify_token);
                    fprintf(file, "gotify_url:%s\n", gotify_url);
                    fclose(file);
                    log_with_timestamp("gotify 的 token,url已写入配置文件");
                }
            }
        } 
    }
      else if (!push_type_found ) {
    log_with_timestamp("未检测到配置文件，需进行设置...");
    // 读取用户的推送方式选择
    get_config_from_user(username, password, token, dingtalk, secret, push_type, wxpush_appToken, wxpush_uids,bark_key, gotify_token, gotify_url);
    // 写入配置文件
    file = fopen(CONFIG_FILE, "w");
    if (file == NULL) {
        perror("无法打开配置文件进行写入");
        return 1;
    } 
    if (!username_found && !password_found) {
        fprintf(file, "#用户配置\n");
        fprintf(file, "%s%s\n", USERNAME_PREFIX, username);
        fprintf(file, "%s%s\n", PASSWORD_PREFIX, password);
    }
    if (!push_type_found) {
    	   fprintf(file, "#推送方式配置：1：pushplus；2：钉钉机器人；3：wxpush; 4:bark; 5: gotify\n");
        fprintf(file, "%s%s\n", PUSH_TYPE_PREFIX, push_type);
    }
   
    if (!token_found && strcmp(push_type, "1") == 0) {
        fprintf(file, "#pushplus配置\n");
        fprintf(file, "%s%s\n", TOKEN_PREFIX, token);
    }
    
    if (!dingtalk_found && strcmp(push_type, "2") == 0) {
        fprintf(file, "#钉钉机器人配置\n");
        fprintf(file, "%s%s\n", DINGTALK_PREFIX, dingtalk);
        fprintf(file, "%s%s\n", SECRET_PREFIX, secret);
    }
    if (!wxpush_found && strcmp(push_type, "3") == 0) {
        fprintf(file, "#Wxpush配置\n");
        fprintf(file, "%s%s\n", WXPUSH_PREFIX, wxpush_appToken);
        fprintf(file, "%s%s\n", WXPUSH_UIDS, wxpush_uids);
    }
    if (!bark_key_found && strcmp(push_type, "4") == 0) {
        fprintf(file, "#bark配置\n");
        fprintf(file, "%s%s\n", BARK_PREFIX, bark_key);
    }
    if (!gotify_token_found && strcmp(push_type, "5") == 0) {
        fprintf(file, "#gotify配置\n");
        fprintf(file, "%s%s\n", GOTIFY_TOKEN, gotify_token);
        fprintf(file, "%s%s\n", GOTIFY_URL, gotify_url);
    }
    fclose(file);
    log_with_timestamp("配置信息已写入 " CONFIG_FILE);
}  
    
    
    // 测试推送
    if (strcmp(push_type, "1") == 0) {
        log_with_timestamp("正在进行测试PushPlus推送...");
        send_pushplus_notification(token, "测试标题", "如你所见,这是一条用于测试推送的信息");
    } else if (strcmp(push_type, "2") == 0) {
        log_with_timestamp("正在进行测试钉钉机器人推送...");
        send_dingtalk_notification(dingtalk, secret, "如你所见,这是一条用于测试推送的信息");
    } else if (strcmp(push_type, "3") == 0) {
        log_with_timestamp("正在进行测试WxPusher推送...");
        send_wxpush_notification(wxpush_appToken, wxpush_uids, "测试标题", "如你所见,这是一条用于测试推送的信息");
    } else if (strcmp(push_type, "4") == 0) {
        log_with_timestamp("正在进行测试bark推送...");
        send_bark_notification(bark_key, "测试标题", "如你所见,这是一条用于测试推送的信息");
    } else if (strcmp(push_type, "5") == 0) {
        log_with_timestamp("正在进行测试gotify推送...");
        send_gotify_notification(gotify_url, gotify_token, "测试标题", "如你所见,这是一条用于测试推送的信息");
    }
	
    // 首次获取IPv6地址
    get_ipv6_address(ipv6, 1, token, dingtalk, secret, push_type, wxpush_appToken, wxpush_uids, bark_key, gotify_url, gotify_token);

    // 首次获取系统运行时间
    int notified = 0;  // 标志变量，表示是否已推送过通知

    // 首次立即调用 login 函数
    printf("Initial login...\n");
    login("http://localhost/goform/login", "0123456789", username, password);

    // 添加自启动服务
    create_and_start_service();

// 轮询的实现
while (1) {
    sleep(12);
    
        // 登录获取cookie，每5分钟获取一次
    login_counter += 12;
        if (login_counter >= 300) { // 每 5 分钟调用一次 login
            printf("Attempting login...\n");
            login("http://localhost/goform/login", "0123456789", username, password);
            login_counter = 0;
        }
        
    // 短信    
   get_sms_list(push_type, token, dingtalk, secret, wxpush_appToken, wxpush_uids,bark_key, gotify_url, gotify_token, g_smsType);
    //ipv6
    get_ipv6_address(ipv6, 0, token, dingtalk, secret, push_type, wxpush_appToken, wxpush_uids, bark_key, gotify_url, gotify_token);
    //重启
    send_system_uptime_notification(token, dingtalk, secret, push_type, wxpush_appToken, wxpush_uids, &notified,bark_key, gotify_url, gotify_token);
    
 // 温度，每分钟查询一次
    temperature_counter += 12;
        if (temperature_counter >= 120) { // 每 1 分钟调用一次 check_temperature
            //printf("温度...\n");
            check_temperature(token, dingtalk, secret, push_type, wxpush_appToken, wxpush_uids, bark_key, gotify_url, gotify_token);
            temperature_counter = 0;
        }
}
    return 0;
}
