发现品速的短信存放在sqlite这个轻量数据库中 但是并没有完整的sqlite3环境
交叉编译补全后 发现sqlite终端交互太难用了 而且每次查短信都要输入sql语句
于是使用go对sqlite进行二次封装 并且加入pushplus推送API （用c语言封装更小）

实现效果如下
[img]http://p0.meituan.net/csc/81b978dc49656b83ce097c7c426f687638372.png[/img]
[img]http://p0.meituan.net/csc/e1fdf9522c0ccb00922618d0c81afbb747340.png[/img]
[img]http://p0.meituan.net/csc/31d96a2c32d3151193a6cdaf20cc6c9658626.png[/img]

每隔15秒获取一次数据库中未读短信 获取成功则通过pushplusAPI推送 推送完成将短信状态设置成已读写回数据库 实现自动推送未读短信至微信公众号

使用方法：有点大 忍忍用着吧 将二进制文件放到/usr/bin目录 空间是够的 给0777权限 在终端输入sql 进行配置 数据库路径：r200的6.0.8版本是：/usrdata/usr/dbm/ 其他版本可能在/m_data/usr/dbm/  token 在pushplus官网http://www.pushplus.plus/扫码关注后获取，提示配置文件已找到后 可使用 nohup sql > output.log 2>&1 & 常驻后台

其他型号应该通用 只要找到database.db这个文件就行

全程除了调用API推送 其他的应该没有任何联网
