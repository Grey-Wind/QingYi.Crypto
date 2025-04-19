using System.Text;
using QingYi.Crypto.DES;
using QingYi.Crypto.XOR;

internal class Program
{
    private static readonly string content = File.ReadAllText("test.abcdefg");

    private static void Main(string[] args)
    {
        #region Xor验证
        if (content == XorCryptoPlus.Xor(XorCryptoPlus.Xor(content, "111"), "111"))
        {
            Console.WriteLine("Xor加密验证成功");
        }
        else
        {
            Console.Write(XorCryptoPlus.Xor(content, "111") + ';');
            Console.WriteLine(XorCryptoPlus.Xor(XorCryptoPlus.Xor(content, "111"), "111"));
        }
        #endregion

        #region Des验证
        if (DesV1Check() == true)
        {
            Console.WriteLine("Des V1加密验证成功");
        }
        else
        {
            Console.WriteLine("Des V1加密验证失败");
        }
        if (DesV2Check() == true)
        {
            Console.WriteLine("Des V2加密验证成功");
        }
        else
        {
            Console.WriteLine("Des V2加密验证失败");
        }
        #endregion

        Console.ReadKey();
    }

    private static bool DesV1Check()
    {
        var des = new QingYi.Crypto.DES.DesPlus.V1.Des();

        string key = des.GenerateKey();

        byte[] input = Encoding.ASCII.GetBytes(content);

        byte[] enc = des.Encrypt(input, Encoding.UTF8.GetBytes(key));
        byte[] decrypted = des.Decrypt(enc, Encoding.UTF8.GetBytes(key));

        if (content == Encoding.ASCII.GetString(decrypted))
        {
            return true;
        }
        else
        {
            //Console.Write(Encoding.ASCII.GetString(decrypted));
            return false;
        }
    }

    private static bool DesV2Check()
    {
        var des = new QingYi.Crypto.DES.DesPlus.V2.Des();
        string enc = des.Encrypt(content, "3B1A9F74C2D8E5F0");
        string dec = des.Decrypt(content, "3B1A9F74C2D8E5F0");
        if (dec == content)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}