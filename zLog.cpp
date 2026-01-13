//
// Created by Administrator on 2024-05-15.
//

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include "zLog.h"



// C接口函数实现
extern "C" void zLogPrint(int level, const char* tag, const char* format, ...) {
    // 检查日志级别
    if (level < CURRENT_LOG_LEVEL) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    
    // 计算格式化后的字符串长度
    int len = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);
    
    if (len <= 0) {
        return;
    }
    
    // 分配足够的内存来存储格式化后的字符串
    char* buffer = (char*)malloc(len);
    if (buffer == NULL) {
        return;
    }
    
    // 再次初始化可变参数列表
    va_start(args, format);
    vsnprintf(buffer, len, format, args);
    va_end(args);
    

    printf("%s\n", buffer);
    sleep(0);  // 等待Android日志输出完毕

    
    free(buffer);
}
