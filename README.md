# 短信转发服务：

该程序主要是为了将CPE中的未读短信转发至推送平台 Pushplus。

经分析品速CPE短信信息全部是通过sqlite3数据库进行存储 于是该程序也使用数据库查询语句进行检索未读短信

为了保证不错漏短信 该程序采用12秒轮询一次 并且设置了开机自启

推荐使用c语言版本！！！！ 懒得修改默认分支



# 使用方法：

将sql二进制程序上传至cpe内/usr/bin目录 然后输入sql运行程序 根据提示输入相关参数

# 2024-10-16更新：

因为go语言编译的程序对比c语言程序要大的多 于是放弃该方案 改用c语言实现 并且完善多几个推送内容和平台

# C语言版本：
https://github.com/mixingh/sms_push/tree/c%E8%AF%AD%E8%A8%80%E7%89%88%E6%9C%AC
# web接口版本：
[https://github.com/mixingh/sms_push/tree/c%E8%AF%AD%E8%A8%80%E7%89%88%E6%9C%AC](https://github.com/mixingh/sms_push/tree/web%E6%8E%A5%E5%8F%A3%E7%89%88%E6%9C%AC)
