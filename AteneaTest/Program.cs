// See https://aka.ms/new-console-template for more information
using Atenea.Crypto.Asymmetric;
using Atenea.Crypto.Asymmetric.HashFunction;
using Atenea.Crypto.Symmetric;

string text = "Hello World";
Console.WriteLine("Start Test AdvancesEncryptionStandard AES");
Console.WriteLine("Text: " + text);
AdvancesEncryptionStandard aes = new AdvancesEncryptionStandard();
string crypto = aes.Encode(text);
Console.WriteLine("Encode: "+crypto);
string plain = aes.Decode(crypto);
Console.WriteLine("Decode: " + plain);
Console.WriteLine("End Test AdvancesEncryptionStandard AES");
Console.WriteLine();
Console.WriteLine();

Console.WriteLine("Start Test RivestShamirAdleman RSA");
Console.WriteLine("Text: " + text);
RivestShamirAdleman rsa = new RivestShamirAdleman();
var keys = rsa.Generate(2048);
rsa = new RivestShamirAdleman(keys[1],true);
crypto = rsa.Encode(text);
Console.WriteLine("Encode: " + crypto);
rsa = new RivestShamirAdleman(keys[0]);
plain = rsa.Decode(crypto);
Console.WriteLine("Decode: " + plain);
Console.WriteLine("End Test AdvancesEncryptionStandard RSA");
Console.WriteLine();
Console.WriteLine();

Console.WriteLine("Start Test MessageDigest5 MD5");
Console.WriteLine("Text: " + text);
MessageDigest5 md5 = new MessageDigest5();
crypto = md5.Encode(text);
Console.WriteLine("Encode: " + crypto);
Console.WriteLine("End Test MessageDigest5 MD5");
Console.WriteLine();
Console.WriteLine();
Console.ReadKey();