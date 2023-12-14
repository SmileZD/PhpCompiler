# PHP代码加密后运行

## 加密，修改KEY和IV

KEY:AES-CBC-PKCS7的128bit密钥，必须是16位字符

IV:AES-CBC-PKCS7的偏移向量，必须是16位字符

PATH1:要加密的文件夹完整路径，会遍历所有文件和子文件夹文件中php后缀文件进行加密

STR1、STR2:两个字符串，在保存加密后的文件时会将原文件路径中的STR1替换为STR2，也就是加密后文件保存到新目录，同时保持文件的路径架构，也保护了源代码

### Java原生代码实现

```java
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Main {

    private static final String KEY = "easyswooleabcdef";
    private static final String IV = "easyswooleabcdef";
    private static final String PATH1 = "/root/xxx/php/abc";
    private static final String STR1 = "abc";
    private static final String STR2 = "efg";
    private static Cipher cipher;

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher= Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES"), new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8)));
        handle(new File(PATH1),STR1,STR2);
    }
    private static void handle(File folder,String str1,String str2) throws IOException,IllegalBlockSizeException, BadPaddingException {
        if (folder.isDirectory()) {
            File[] files = folder.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        handle(file,str1,str2);
                    } else {
                        if (file.getName().endsWith(".php")) {
                            String content = Files.readString(Paths.get(file.getAbsolutePath()));
                            String result =Base64.getEncoder().encodeToString(cipher.doFinal(content.substring(5).getBytes(StandardCharsets.UTF_8)));
                            String finalResult = "<?php return easy_compiler_decrypt('"+result+"');";
                            try {
                                String filePath=file.getAbsolutePath().replace(str1, str2);
                                File newFile = new File(filePath);
                                File parentDir = newFile.getParentFile();
                                if (!parentDir.exists()) {
                                    parentDir.mkdirs();
                                }
                                FileWriter writer = new FileWriter(newFile);
                                writer.write(finalResult);
                                writer.close();
                                System.out.println("加密文件到: " + filePath);
                            }catch (Exception th){
                                System.out.println(th.getMessage());
                            }
                        }
                    }
                }
            }
        }
    }
}
```

### golang需要先安装goframe框架：

```shell
go get -u "github.com/gogf/gf/v2/frame/g"
```

```golang
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/text/gstr"
)

var (
	KEY   = "easyswooleabcdef"
	IV    = "easyswooleabcdef"
	PATH1 = "/root/xxx/php/abc"
	STR1  = "abc"
	STR2  = "def"
)

func main() {
	handle(PATH1, STR1, STR2)
}

func handle(path string, str1 string, str2 string) {
	var (
		result  = ""
		newPath = ""
	)
	list, _ := gfile.ScanDir(path, "*.php", true)
	for _, v := range list {
		data := []byte(gstr.StrEx(gfile.GetContents(v), "<?php"))
		paddingSize := aes.BlockSize - len(data)%aes.BlockSize
		paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
		data = append(data, paddingText...)
		block, _ := aes.NewCipher([]byte(KEY))
		mode := cipher.NewCBCEncrypter(block, []byte(IV))
		mode.CryptBlocks(data, data)
		result = base64.StdEncoding.EncodeToString(data)
		newPath = gstr.Replace(v, str1, str2)
		_ = gfile.PutContents(newPath, "<?php return easy_compiler_decrypt('"+result+"');")
		fmt.Println("加密文件到：" + newPath)
	}
}

```

## 解密

### 安装php扩展（可以在自己设备上安装，最后将扩展的so文件上传到目标服务器php扩展文件夹里）

```shell
git clone https://github.com/SmileZD/PhpCompiler
cd PhpCompiler
#修改src\config.h文件夹中的KEY、IV，要和加密时使用的一致
phpize
./configure
make
make install
#会输出扩展所在文件夹，到该文件夹下载easy_compiler.so上传到同架构目标服务器的php扩展文件夹里即可
```
目标服务器php的配置文件php.ini和php-cli.ini最后一行添加

```shell
extension=easy_compiler.so
```
重启php即可
