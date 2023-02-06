using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace HashAES256demo
{
    internal class Program
    {

        static void Main(string[] args)
        {
            Aes256Base64Class serviceBase64 = new Aes256Base64Class();
            Aes256HexClass serviceHex = new Aes256HexClass();


            Console.WriteLine("Enter data:");
            string data = Console.ReadLine();
            Console.WriteLine("--------------");
            Console.WriteLine("Choose Method:");
            Console.WriteLine("Press (1): Encrypt");
            Console.WriteLine("Press (2): Decrypt");
            string method = Console.ReadLine();
            Console.WriteLine("--------------");
            Console.WriteLine("Output Text Format:");
            Console.WriteLine("Press (1): HEX");
            Console.WriteLine("Press (2): Base64");
            string type = Console.ReadLine();
            Console.Clear();
            data = data.Replace(" ", "");

            if (method == "1")
            {
                Console.WriteLine("Starting");
                string result = "";
                if (type == "1")
                {
                    result = serviceHex.Encrypt(data);
                } else if(type == "2")
                {
                    result = serviceBase64.Encrypt(data);
                }
                Console.Clear();
                Console.WriteLine("--------------");
                Console.WriteLine("Encrypted String: " + result);
            } else if (method == "2")
            {
                Console.WriteLine("Starting");
                string result = "";
                if (type == "1")
                {
                    result = serviceHex.Decrypt(data);
                }
                else if (type == "2")
                {
                    result = serviceBase64.Decrypt(data);
                }
                Console.Clear();
                Console.WriteLine("--------------");
                Console.WriteLine("Decrypted String: " + result);
            } else
            {
                Console.WriteLine("End Job!");
            }
            Console.ReadKey();
        }
    }
}
