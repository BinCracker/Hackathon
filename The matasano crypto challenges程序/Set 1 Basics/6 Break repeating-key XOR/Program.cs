using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace prob6
{
    class Program
    {

        public static int calc(string a, string b) //计算edit distance/Hamming distance
        {
            while (a.Length < b.Length) a += '\x0';
            while (b.Length < a.Length) b += '\x0';
            int ret = 0;
            for (int i = 0; i < a.Length; i++)
            {
                int temp = a[i] ^ b[i];
                for (int j = 0; j < 8; j++) if ((temp & (1 << j)) != 0) ret++;
            }
            return ret;
        }
        public static string cipher = string.Empty;
        public static int[] bestsize = new int[3] { 0,0,0,};
        public static float[] bestscore = new float[3] { 1000000, 1000000, 1000000 };
        public static double[] letterFrequency = new double[1001];
        public static void findKey(string cipher, int numblocks) //枚举key的长度，计算较优的edit distance/Hamming distance
        {
            int index = 0;
            for (int i = 2; i <= 40; i++)
            {
                string str1 = cipher.Substring(0,  i * numblocks);
                string str2 = cipher.Substring(i * numblocks, i * numblocks);
                int dif = calc(str1, str2);
                float score = (dif / (float)(numblocks * i));
                if (score < bestscore[index])
                {
                    bestsize[index] = i;
                    bestscore[index] = score;
                    index = 0;
                    if (bestscore[1] > bestscore[0]) index = 1;
                    if (bestscore[2] > bestscore[index]) index = 2;
                }
            }
        }
        public static string[] split(string cipher, int numblocks) //分块，使得每一块都是用同一个字母异或的
        {
            string[] ret = new string[30];
            for (int i = 0; i < numblocks;i++)
            {
                for (int j = i; j < cipher.Length; j += numblocks)
                    ret[i] += cipher[j];                
            }
            return ret;
        }
        public static double calcMSG(string cipher)     //  根据英文字母的频率，计算这个文本的值，越大越趋向于正常文本
        {
            int[] cnt = new int[1000];
            Array.Clear(cnt, 0, 1000);
            double ret = 0;
            for (int i = 0; i < cipher.Length; i++)
            {
                if (cipher[i] < 128)
                {
                    cnt[Char.ToUpper(cipher[i])]++;
                }
            }
            for (int i = 'A'; i <='Z';i++)
            {
                ret += letterFrequency[i] * cnt[i];
            }
            ret += letterFrequency[' '] * cnt[' '];
            ret /= cipher.Length;
            return ret;
        }
        public static char  calcKey(string cipher)  //计算key，枚举每个blocks的异或字符相加就是最后的key
        {
            char ret = ' ' ;
            double bestMSG = 0.0;            
            char[] tmp = new char[10000];
            Array.Clear(tmp, 0, 10000);
            try
            { for (int i = 0; i < 256; i++)
                {
                    //string tmp = cipher;
                    for (int j = 0; j < cipher.Length; j++)
                        tmp[j] = (char)(cipher[j] ^ i);
                    double tt = calcMSG(new string(tmp));
                    if (tt > bestMSG)
                    {
                        bestMSG = tt;
                        ret = (char)i;
                    }
                }
            }catch(Exception e)
            {

            }
            return ret;
        }
         static void Main(string[] args)
        {
            letterFrequency['A'] = .082;
            letterFrequency['B'] = .015;
            letterFrequency['C'] = .028;
            letterFrequency['D'] = .043;
            letterFrequency['E'] = .127;
            letterFrequency['F'] = .022;
            letterFrequency['G'] = .020;
            letterFrequency['H'] = .061;
            letterFrequency['I'] = .070;
            letterFrequency['J'] = .002;
            letterFrequency['K'] = .008;
            letterFrequency['L'] = .040;
            letterFrequency['M'] = .024;
            letterFrequency['N'] = .067;
            letterFrequency['O'] = .075;
            letterFrequency['P'] = .019;
            letterFrequency['Q'] = .001;
            letterFrequency['R'] = .060;
            letterFrequency['S'] = .063;
            letterFrequency['T'] = .091;
            letterFrequency['U'] = .028;
            letterFrequency['V'] = .010;
            letterFrequency['W'] = .023;
            letterFrequency['X'] = .001;
            letterFrequency['Y'] = .020;
            letterFrequency['Z'] = .001;
            letterFrequency[' '] = .200;
            //Console.WriteLine(calc("this is a test", "wokka wokka!!!"));
            for (int i = 0; i < 64; i++)
            {
                cipher +=Encoding.ASCII.GetString( Convert.FromBase64String(Console.ReadLine()));
            }
            //Console.WriteLine(cipher);
            findKey(cipher, 20);
            Console.WriteLine(bestsize[1]);
            string[] splitres = split(cipher, bestsize[1]);
            //bestsize[1] = 29;
            //Console.WriteLine("Azure");
            string key = string.Empty;
            for (int i = 0; i < splitres.Length; i++)
            {
                key += calcKey(splitres[i]);
            }
            Console.WriteLine("Key : "+ key);
            //key = Terminator X: Bring the noise
            int pos = 0;
            for (int i  = 0; i < cipher.Length;i++)
            {
                Console.Write((char)(cipher[i] ^ key[pos]));
                pos++;
                if (pos == key.Length) pos = 0;
            }
        }
    }
}
