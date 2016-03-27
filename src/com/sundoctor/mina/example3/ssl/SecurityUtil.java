package com.sundoctor.mina.example3.ssl;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Created by liqingsong on 3/25/16.
 */
public class SecurityUtil {

        public static void main(String[] args) throws Exception
        {
            String privatePath = "/Users/liqingsong/Projects/MinaWithSSLCA/src/com/sundoctor/mina/example3/ssl/DK01Pri.key"; // 准备导出的私钥
            String publicPath = "/Users/liqingsong/Projects/MinaWithSSLCA/src/com/sundoctor/mina/example3/ssl/DK01Pub.key"; // 准备导出的公钥
            PrivateKey privateKey = getPrivateKeyFromStore();
            createKeyFile(privateKey, privatePath);
            PublicKey publicKey = getPublicKeyFromCrt();
            createKeyFile(publicKey, publicPath);

            test(privateKey, publicKey);
            test(publicKey, privateKey);
            test(privateKey, privateKey);
            test(publicKey, publicKey);
        }
        private static PrivateKey getPrivateKeyFromStore() throws Exception
        {
            String alias = "DK01"; // KeyTool中生成KeyStore时设置的alias
            //Much stronger than JKS, access directly after JDK1.4
            String storeType = "JCEKS"; // KeyTool中生成KeyStore时设置的storetype
            char[] pw = "123456".toCharArray(); // KeyTool中生成KeyStore时设置的storepass
            String storePath = "/Users/liqingsong/Projects/MinaWithSSLCA/src/com/sundoctor/mina/example3/ssl/DK01.store"; // KeyTool中已生成的KeyStore文件
            storeType = null == storeType ? KeyStore.getDefaultType() : storeType;
            KeyStore keyStore = KeyStore.getInstance(storeType);
            InputStream is = new FileInputStream(storePath);
            keyStore.load(is, pw);
            // 由密钥库获取密钥的两种方式
            // KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(pw));
            // return pkEntry.getPrivateKey();
            return (PrivateKey) keyStore.getKey(alias, pw);
        }
        private static PublicKey getPublicKeyFromCrt() throws CertificateException, FileNotFoundException
        {
            String crtPath = "/Users/liqingsong/Projects/MinaWithSSLCA/src/com/sundoctor/mina/example3/ssl/DK01.crt"; // KeyTool中已生成的证书文件
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream in = new FileInputStream(crtPath);
            Certificate crt = cf.generateCertificate(in);
            PublicKey publicKey = crt.getPublicKey();
            return publicKey;
        }
        private static void test(Key encryptKey, Key decryptKey) throws Exception
        {
            System.out.println();
            String data = encryptKey.getClass().getSimpleName() + "加密" + " ~ " + decryptKey.getClass().getSimpleName() + "解密";
            System.out.println("明文 ~ " + data);
            byte[] enb = Base64.encode(RSAencrypt(encryptKey, data.getBytes()));
            String en = new String(enb);
            System.out.println("加密结果 ~ " + new String(enb));
            byte[] deb = Base64.decode(en);
            byte[] result = RSAdecrypt(decryptKey, deb);
            System.out.println("解密结果 ~ " + new String(result));
        }
        private static byte[] RSAencrypt(Key pk, byte[] data) throws Exception
        {
            Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            int blockSize = cipher.getBlockSize();
            int outputSize = cipher.getOutputSize(data.length);
            int leavedSize = data.length % blockSize;
            int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
            byte[] raw = new byte[outputSize * blocksSize];
            int i = 0;
            while (data.length - i * blockSize > 0)
            {
                if (data.length - i * blockSize > blockSize)
                {
                    cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
                }
                else
                {
                    cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
                }
                i++;
            }
            return raw;
        }
        private static byte[] RSAdecrypt(Key pk, byte[] raw) throws Exception
        {
            Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, pk);
            ByteArrayOutputStream bout = null;
            try
            {
                bout = new ByteArrayOutputStream(64);
                int j = 0;
                int blockSize = cipher.getBlockSize();
                while (raw.length - j * blockSize > 0)
                {
                    bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
                    j++;
                }
                return bout.toByteArray();
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                if (bout != null)
                {
                    try
                    {
                        bout.close();
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();
                    }
                }
            }
        }
        private static void createKeyFile(Object key, String filePath) throws Exception
        {
            FileOutputStream fos = new FileOutputStream(filePath);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(key);
            oos.flush();
            oos.close();
        }

}
