# ~~为了信安吹逼大赛~~ (凉了)

### 初步构想

* hook程序的read,send,recv调用，拦截程序的IO，对数据进行加解密来实现对程序的保护

### 细节
---
#### 网络
* loader会将程序启动，并且将hookdl注入
* hookdl在加载的时候会加载hook
* 在第一次调用hook函数的时候sgx会进行初始化操作 
  >sgx初始化操作无法在dllmain中完成，具体见手册
* 初始化的过程中会和服务器交换通信用的密钥（这个地方目前还不是很完善）
* 完成之后会将程序所有流量用这个密钥加密之后发送给中转服务器
* 中转服务器根据交换密钥时的token信息获取对应的密钥（不完善）
* 中转服务器将流量解密之后转发给真正的服务器
* 真正的服务器传回的消息又会被中转服务器加密之后发给应用程序


#### 读写
* 目前读文件时解密的密钥还是硬编码，需改进。


### 工程划分

---
####

* loader：加载程序
* hookdl：注入用dll
* safeIO：sgx内部代码
* server：认证服务器+转发服务器
* sgxtest：sgx代码测试用工程
* dlltest：注入用代码测试工程
