using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
namespace crypto
{
    class set3_19
    {
        public static List<byte[]> cipherbyte = new List<byte[]>();
        public static List<string> plaintext = new List<string>();
        public static List<string> ciphertext = new List<string>();
        public static char[] ans = new char[100];
        public static string key = string.Empty;
        public static HashSet<string> finalans = new HashSet<string>();

        public static void process()
        {
            for (int i = 0;  i < 40 ; i++)
            {
                string temp = Console.ReadLine();
                cipherbyte.Add( Convert.FromBase64String(temp));
                //Console.WriteLine(Encoding.ASCII.GetString(cipherbyte[i]));
                plaintext.Add(Encoding.ASCII.GetString(cipherbyte[i]));
                Console.WriteLine(plaintext[i]);
            }
            /*
            相当于在流密码中用了多次同样的key
            假设key = "123456789009876543212345678909876543234567890987654323456789087654324567898976"
            */
            key = "123456789009876543212345678909876543234567890987654323456789087654324567898976";
            for (int i = 0; i < plaintext.Count; i++)
            {
                string temp = string.Empty;
                for (int j = 0; j < plaintext[i].Length; j++)
                {
                    temp += (char)(plaintext[i][j] ^ key[j]);
                }
                ciphertext.Add(temp);
                Console.WriteLine(ciphertext[i]);
            }
            for (int i = 0; i < 40; i++)
            {
                Array.Clear(ans, 0, 100);
                for (int k = 0; k < ciphertext[i].Length; k++)
                {
                    int cnt = 0;
                    for (int j = 39; j >=0; j--)
                    {
                        if (k >= ciphertext[j].Length) continue;
                        if (i == j) continue;
                        if ((ans[k] == ' ') == false)
                        {
                            if (Char.IsLetter((char)((ciphertext[i][k]) ^ (ciphertext[j][k]))))
                            {
                                cnt++;
                                if (cnt > 20) ans[k] = ' ';     //异或结果有20以上的字母 则假设这一位为空格
                                else
                                {                                   
                                        ans[k] = (char)((ciphertext[i][k]) ^ (ciphertext[j][k]));
                                }
                            }
                        }
                        finalans.Add(new string(ans));                                                
                    }
                }               
            }
            //输出全部中间结果，可以基本还原原文 猜测部分就不写了=。=
            foreach ( var t in finalans)
            {
                for (int i = 0; i < t.Length; i++)
                    Console.Write(Char.ToLower(t[i]));
                Console.WriteLine();
            }
            
        }
    }
}
