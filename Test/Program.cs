using QingYi.Crypto.XOR;

string content = File.ReadAllText("test.abcdefg");

if (content == XorCryptoPlus.Xor(XorCryptoPlus.Xor(content, "111"), "111"))
{
    Console.WriteLine("Xor加密验证成功");
}
else
{
    Console.Write(XorCryptoPlus.Xor(content, "111") + ';');
    Console.WriteLine(XorCryptoPlus.Xor(XorCryptoPlus.Xor(content, "111"), "111"));
}

Console.ReadKey();
