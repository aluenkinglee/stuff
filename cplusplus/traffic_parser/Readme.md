犯了一个愚蠢的问题，让我碰到了这么个内容错误的bug

```bash
*** glibc detected *** ./main: free(): invalid next size (fast): 0x0000000001dd8590 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x76d76)[0x7fd77419fd76]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x6c)[0x7fd7741a4aac]
/usr/lib/x86_64-linux-gnu/libpcap.so.0.8(+0x1b470)[0x7fd774e2e470]
/usr/lib/x86_64-linux-gnu/libpcap.so.0.8(pcap_loop+0x2f)[0x7fd774e1fecf]
./main[0x401869]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xfd)[0x7fd774147ead]
./main[0x401001]
======= Memory map: ========
00400000-00402000 r-xp 00000000 08:08 1982169                            /home/kinglee/github/stuff/cplusplus/traffic_parser/main
00602000-00603000 rw-p 00002000 08:08 1982169                            /home/kinglee/github/stuff/cplusplus/traffic_parser/main
01dc8000-01de9000 rw-p 00000000 00:00 0                                  [heap]
7fd770000000-7fd770021000 rw-p 00000000 00:00 0 
7fd770021000-7fd774000000 ---p 00000000 00:00 0 
7fd774129000-7fd7742a9000 r-xp 00000000 08:08 2097171                    /lib/x86_64-linux-gnu/libc-2.13.so
7fd7742a9000-7fd7744a9000 ---p 00180000 08:08 2097171                    /lib/x86_64-linux-gnu/libc-2.13.so
7fd7744a9000-7fd7744ad000 r--p 00180000 08:08 2097171                    /lib/x86_64-linux-gnu/libc-2.13.so
7fd7744ad000-7fd7744ae000 rw-p 00184000 08:08 2097171                    /lib/x86_64-linux-gnu/libc-2.13.so
7fd7744ae000-7fd7744b3000 rw-p 00000000 00:00 0 
7fd7744b3000-7fd7744c8000 r-xp 00000000 08:08 2097156                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd7744c8000-7fd7746c8000 ---p 00015000 08:08 2097156                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd7746c8000-7fd7746c9000 rw-p 00015000 08:08 2097156                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7fd7746c9000-7fd77474a000 r-xp 00000000 08:08 2097168                    /lib/x86_64-linux-gnu/libm-2.13.so
7fd77474a000-7fd774949000 ---p 00081000 08:08 2097168                    /lib/x86_64-linux-gnu/libm-2.13.so
7fd774949000-7fd77494a000 r--p 00080000 08:08 2097168                    /lib/x86_64-linux-gnu/libm-2.13.so
7fd77494a000-7fd77494b000 rw-p 00081000 08:08 2097168                    /lib/x86_64-linux-gnu/libm-2.13.so
7fd77494b000-7fd774a33000 r-xp 00000000 08:08 1314662                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.17
7fd774a33000-7fd774c33000 ---p 000e8000 08:08 1314662                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.17
7fd774c33000-7fd774c3b000 r--p 000e8000 08:08 1314662                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.17
7fd774c3b000-7fd774c3d000 rw-p 000f0000 08:08 1314662                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.17
7fd774c3d000-7fd774c52000 rw-p 00000000 00:00 0 
7fd774c52000-7fd774c72000 r-xp 00000000 08:08 2097174                    /lib/x86_64-linux-gnu/ld-2.13.so
7fd774e0e000-7fd774e13000 rw-p 00000000 00:00 0 
7fd774e13000-7fd774e4b000 r-xp 00000000 08:08 1331924                    /usr/lib/x86_64-linux-gnu/libpcap.so.1.3.0
7fd774e4b000-7fd774e4d000 r--p 00037000 08:08 1331924                    /usr/lib/x86_64-linux-gnu/libpcap.so.1.3.0
7fd774e4d000-7fd774e4e000 rw-p 00039000 08:08 1331924                    /usr/lib/x86_64-linux-gnu/libpcap.so.1.3.0
7fd774e4e000-7fd774e4f000 rw-p 00000000 00:00 0 
7fd774e6d000-7fd774e71000 rw-p 00000000 00:00 0 
7fd774e71000-7fd774e72000 r--p 0001f000 08:08 2097174                    /lib/x86_64-linux-gnu/ld-2.13.so
7fd774e72000-7fd774e73000 rw-p 00020000 08:08 2097174                    /lib/x86_64-linux-gnu/ld-2.13.so
7fd774e73000-7fd774e74000 rw-p 00000000 00:00 0 
7fff1591a000-7fff1593b000 rw-p 00000000 00:00 0                          [stack]
7fff159ff000-7fff15a00000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
已放弃
``` 

对于这个问题，当时表示怎么会出现内存错误？我指针根本没有指错啊！那块内存也没有回收阿！！原来的程序比较大，所以我就抽象写了个简单的，慢慢找。

```c++
#include <string>
#include <iostream>
#include <algorithm>
#include <vector>

using namespace std;
typedef class packet
{
    private:
    int len;
    char* data;
    public:
    packet(int l,char * p)
    {
	//注意这里，开始我写成了这样，一开始写顺了...
	//我本意是想申请一个长度为l的连续内存区域。
	//结果本意成为了申请了一个单位的内存，并给它赋值！！
        data=new char(l);
        //应该写成这样
        //data=new char[l];
        copy(p,p+l,data);
        len = l;
    }
 
    packet(const packet& p)  
    {
        this->len=p.len;
        data=new char[len];
        copy(p.data, p.data+len,data);
    }
    
    packet& operator=(const packet& p)
    {
        this->len = p.len;
        this->data = new char[this->len];
        copy(p.data, p.data+len,this->data);
        return *this;
    } 
    
    ~packet(){delete[] data;}
    char* get_data(){return data;}

}packet;

int main()
{
    vector<packet> stream;
    char *t = "hello world.\n";
    packet p(5,t);
    cout << p.get_data( )<< endl;
    stream.push_back(p);
    cout << stream[0].get_data() <<endl;
    return 0;
}
```

编译运行就会出错。

```
g++ test.cc -o main 
```

所以，上述的语句是没有申请够足够的内存(只申请了一个，却按照那个长度来copy！！当然会出现数据覆盖的错误，这个属于语言错误)，所以会造成之后的内存覆盖，导致出错。有意思的是在windows平台上，我试过，是不会提示你出错的。
不过确实可以看到运行过程中不合理的地方。比如数据被覆盖了overlapping!（实验平台debian 7 ，g++ (Debian 4.7.2-5) 4.7.2
windows是win7 + mingw）



```
*** glibc detected *** ./main: double free or corruption (fasttop): 0x0000000000e55010 ***
```

另外一点，在实际使用过程中，还是尽量不要混合使用malloc 和delete/delete[]

* 使用malloc分配的内存尽量使用free释放掉

* 使用new分配的内存，看情况，若是对象类型本身就是数组类型，使用delete[],否则使用delete释放掉内存

* 使用new[]分配内存的，必须使用delete[] 来释放掉内存。否则只是释放掉了内存区域的第一个从而造成内存泄漏。

>> 参考

* ['** glibc detected *** ./main: free(): invalid next size (fast):'](http://stackoverflow.com/questions/18389313/glibc-detected-main-free-invalid-next-size-fast)

* ['好好使用memcpy'](http://www.cplusplus.com/reference/cstring/memcpy/?kw=memcpy)