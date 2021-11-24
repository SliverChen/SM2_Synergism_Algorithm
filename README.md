# SM2_Synergism_Algorithm

Create in 2021 / 11 / 16

## 1、Instruction

### SM2协同计算算法

### 关键点

- 随机数的生成过程

    关于密码学的随机数生成说明: https://github.com/Tencent/secguide/blob/main/C%2CC%2B%2B%E5%AE%89%E5%85%A8%E6%8C%87%E5%8D%97.md#44--%E5%BF%85%E9%A1%BB%E5%9C%A8%E9%9C%80%E8%A6%81%E9%AB%98%E5%BC%BA%E5%BA%A6%E5%AE%89%E5%85%A8%E5%8A%A0%E5%AF%86%E6%97%B6%E4%B8%8D%E5%BA%94%E4%BD%BF%E7%94%A8%E5%BC%B1prng%E5%87%BD%E6%95%B0

    具体实现参考(openssl):

    https://www.openssl.org/docs/man3.0/man3/BN_rand_range.html

    ```c++
    #include<openssl/bn.h>
    //...
    //...获取类型转换后的基点的阶
    BIGNUM* cn;                     
    BIGNUM* bn;
    bn = BN_new();                  //申请内存空间
    int bits = 8 * NUM_ECC_DIGITS;  //随机数的比特长度
    do{
    	BN_rand_range(bn,cn);       //生成[0,cn)的随机数
    }while(BN_is_zero(bn));         //一般生成[1,cn-1]的随机数，因此需要检验是否为0
    
    char* randStr = BN_bn2hex(bn);  //将BIGNUM类型转换为char*
    
    //..处理randStr
    
    BN_free(bn);                    //处理完后释放申请的内存
    BN_free(cn);
    ```

    

- 协同签名的过程

- 协同解密的过程

- 注释的规范 参考: https://www.jianshu.com/p/9464eca6aefe

- 主要使用的语言
    

### 设计难点一(首要目标)

- 如何实现参与签名或解密的双方进行安全的数据传输

### 目前想到的设计的方案

- 用一个类来定义客户端/服务端
- 类中成员包括socket, socketAddr, privateKey等变量
- 同时还需要包括在协同计算过程中对数据的计算函数(计算函数对外不可见)

#### 1) 针对上面的第一点的设计方案

##### 1.1 定义两个类来分别定义客户端和服务端

- 由于客户端与服务端的计算有所差异，不能单纯将这个类统称为客户端或服务端
- 但是客户端与服务端有共同的接口以及部分成员，对此我们可以利用基类继承的方式
- 先定义一个虚基类来存储双方共同的部分，再利用继承生成客户端/服务端，各自实现自己的部分

##### 1.2 定义一个通用的类来定义主处理方和协助方

- 显然方案1.1中定义两个类来分别定义会造成内存消耗大的情况，并且维护的时候需要同时处理两个类的细节部分，维护复杂度变高，因此考虑使用一个通用的类来定义双方
- 在构造的时候确认身份是主处理方还是协助方
- 内部函数同时提供主处理方与协助方的细节实现

##### 补充一: 客户端与服务端的结构

- 如果用类实现客户端/服务端，那么在C环境下将会不兼容
- 目前网上大多数的SM2算法都是在C环境下实现的，猜想可能在实际应用当中，SM2算法的环境是在C环境下使用的，此时需要考虑兼容性的问题
- 对于第一点的设计方案：如果想要提高兼容性，可以定义结构体来定义客户端/服务端，但是这样的话所有的函数都会被暴露出来(为什么会觉得将所有函数暴露出来是不安全的?)

##### 补充二: 数据传输的格式(1)

- 考虑到socket自带的send()和recv()函数处理的数据类型是char*，但是我们在作数据传输的时候一般都是传输椭圆曲线上的点，由于椭圆曲线上的点包含了x和y两个成员，所以我们不能直接将数据传输过去
- 比较直观的方法就是将这两个成员拼接成一串字符，因为两个成员的长度是给定的，是uint8_t[NUM_ECC_DIGITS],我们可以在将要发送的数据前面设置好首部对数据描述(包括定义和长度),后面再接上拼接的字符串即可
- 接收方只需要解析首部的内容,根据对应的长度来对数据进行提取
- 由于在该算法下，所有涉及到的数据传输都没有超过10个点的传输，也就是说，首部仅仅是一个字符对应的整数，不需要再对数据进行序列化的操作。

##### 补充三: 数据传输的格式(2)

- 从补充二可以知道数据的首部起到关键的作用，对后续的数据提取有补充性的说明
- 因此我们如何设置合理的首部是比较关键的
- 不难推出首部包含两个部分(数据的定义和数据的长度)
- 对于数据的定义，因为协同签名和解密中间传输的步骤有限，我们可以利用整型的宏定义来定义每一个传输的步骤，这样数据的定义就可以用定长的整型类型来规定
- 同时根据我们传输的数据类型，不难发现数据的长度是控制在一个比较小的范围内的，所以我们同样可以利用int类型来描述数据的长度

##### 补充四: Socket

- 为了确保连接与断连，发送与接收的有效性，需要对socket网络编程有比较深入的理解
- 连接与断连的关键点在于连接的时机以及断连的实现
- 连接的时机可以放在将要进行公钥生成，协同签名或者协同解密之前
- 断连的操作可以参考: https://www.cnblogs.com/embedded-linux/p/7468442.html
- 发送的操作需要注意数据长度的设置，避免漏传
- 接收的操作需要注意数据的完整性，避免被截断


#### 2) 针对上面的第三点的设计方案

##### 2.1 将数据计算函数用一个接口函数来管理

- 可以将数据计算各自封装成一个独立的函数，然后用一个接口函数来管理，传入参数包括顺序号和可变参数
- 根据顺序号，利用switch来选择哪一步的计算函数(类内调用对外不可见的函数)
- 每次的数据计算包括本次计算过程还有传输下一步数据的过程(或者返回数据)

##### 2.2 直接调用每一步的数据计算函数

- 将每一步数据计算封装成一个函数
- 计算的时候直接调用对应的函数

上面两个针对第三点的方案有共同的缺点：

将发送到对端这个操作作为一个节点，分别封装每一节的计算过程到函数中，这样做不易于维护，在修改某一式子可能需要调整所有有关的函数函数

##### 2.3 直接将整个协同计算写到一个函数下

- 需要注意的是在发送完数据给对端时，如果后续还有计算，则需要将线程设置为阻塞态，不断监听接收通道
- 直到有数据到达为止，协同计算函数再往下计算

##### 补充: 数据传输接收的结构转换

- 注意到每次参与协同计算传递的数据都是椭圆曲线上面的点(EccPoint类型)
- 但是socket提供的发送函数传输的是char* 类型的数据，因此需要对EccPoint类型进行处理转换为char* 类型
- EccPoint的结构由x和y构成，x和y都是32位的16进制数组构成，好在数据长度是固定的，我们只需要在发送的时候将x和y拼接到同一个char字符串下再进行发送。
- 接收的时候则根据定长取对应长度的字符串来对应EccPoint的x和y

---

### 设计难点二(次要目标)

- 如何设计满足多个客户端同时请求操作，服务端能正确与他们正常协同计算



#### 说明

首先我们要明确，该算法面向的是一个服务器，多个客户端的构造，即服务器需要参与每个客户端的协同计算，并且各自不影响内部的计算，考虑到一个服务器对应多个客户端的情况。再结合上面的对SM2服务端的设计的思考，应该使用独立的两个类来定义客户端与服务端



#### 方案一

针对这种情况，我们优先考虑使用多线程：

- 服务端开一个线程监听连接请求(不间断)
- 当出现一个客户端发出连接请求，另开一个线程为该客户端服务
- 当客户端完成公钥生成，签名或解密时，服务端及时清掉线程，防止数据泄露



#### 补充: 线程的设计

- 对于上面的方案，可能后续需要考虑限制同时开辟的线程的数量，控制服务器的压力
- 同时，为了实现与每个客户端互不影响地进行协同计算，在新开的线程当中应当包括数据的传输和数据的接收接口，即整个完整的计算过程都应在这个线程中完成



### 设计难点三

- 如何利用参考代码模拟出完整的过程

#### 说明

- 通过大致浏览参考代码，我们能够大致对一些步骤进行仿照编写
- 但是有两个地方：
- 1、我们自定义的公式运算需要具体使用哪一个函数来计算
- 2、在加密和解密的过程中，原作者在几处地方都对运算结果进行了翻转的操作，并且没有给出这一步的意义。
- 通过测试发现，如果没有翻转的操作，最后将无法得出正确的结果，并且可能中途会出现hash error 或者 not on curve的错误

#### 解决方案

- 通过不断理解原作者的encrypt和decrypt过程，并且将其中的步骤理解透彻
- 可以先在参考代码的基础上，先不实现协同计算的过程，将原有的计算公式修改为我们自定义的公式，然后测试当前想法的可行性，反复测试


---

### 设计疑问

- 选择哪一种语言作为主要语言

#### 说明

通过深入研究并且编写新的代码后，由于我主要使用的是C++编写，在某些类型或语法的使用上与C存在互斥的情况，比如string, cout, class的使用，以及像一些类别转换上面有很大的差异

C++比C的优点是提供了很多安全的接口来实现一些已有的功能，比如类别转换和对不定长度的字符串进行操作等

为了能够让整个算法正常在C++环境下运行，我们需要：

- 对于原有参考算法，在没有修改太多的情况下照常使用C语言编写，同时在定义的时候加上extern "C"语句确保C++能够正确运行C环境下的代码
- 防止出现C语法在C++环境下编译(大概率报错)
- 对于新加的代码，如果存在使用原有参考算法内部的函数接口，需要注意语法的兼容性
- 将只能在C下实现的代码归到一类(用.c实现的头文件或者在.cpp文件下使用extern "C"来定义)
- 将只能在C++下实现的代码归到一类(用.cpp实现的头文件)
- 避免在.c实现的头文件下出现有关C++语法的代码

#### 进度(11.23)

- 目前正在测试整个算法在不加入协同计算时的计算的准确性，也就是直接在一个函数内实现加密，一个函数内实现解密
- 但是由于环境的不兼容性，导致在编译测试代码的时候出现了很多问题
- 需要从头开始将代码逐一整理归类(基础架构布置的太差了)

#### 进度(11.24)

- 注意到参考算法中使用了extern "C"的语法来区分C/C++环境，因此我们可以直接在原有基础上只将文件后缀名替换为.cpp即可
- 同时还要注意新加的CPP代码不要放在extern "C"下，这样会导致C编译器编译C++的代码从而出现编译出错等问题
- 当前的主要目的是将某个功能放到合适的头文件下