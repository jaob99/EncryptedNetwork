using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Net;
using System.Threading;

using NetworkTools.EncryptedNetwork;
using NetworkTools.Tools;

namespace encnettest
{
    /// <summary>
    /// Example programme
    /// </summary>
    class Program
    {
        static int PORT = 10110;
        static void serv()
        {
            TcpListener tcpl = new TcpListener(PORT);
            tcpl.Start();
            var sock = tcpl.AcceptSocket();

            EncryptedNetworkStream encnet = new EncryptedNetworkStream(sock, new System.Security.Cryptography.RSACryptoServiceProvider());
            encnet.ExchangeRSAKeys();
            Console.WriteLine("[server]: Key exchange ok (foreign key: " + encnet.ForeignKey.ToByteArray().SHA1Hash().Hex().ToLower());
            Console.WriteLine("[server]: \t(us: " + encnet.LocalKey.ToByteArray().SHA1Hash().Hex().ToLower());

            encnet.SetEncryptedRead();
            Console.WriteLine("[server]: Read AES key ok");

            uint read = encnet.ReadValue<uint>();
            Console.WriteLine("[server]: Read data ok: 0x" + read.ToString("X"));

            encnet.UnsetEncryptedRead();

            encnet.SetEncryptedWrite();
            Console.WriteLine("[server]: Write AES key ok");

            encnet.WriteValue<uint>(0xABAD1DEA);

            Console.WriteLine("[server]: Write data ok");
            encnet.UnsetEncryptedWrite();

            Console.WriteLine("[server]: Close");
            encnet.Close();

            tcpl.Stop();
        }
        static void clie()
        {
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sock.Connect(new IPEndPoint(IPAddress.Loopback, PORT));
            EncryptedNetworkStream encnet = new EncryptedNetworkStream(sock, new System.Security.Cryptography.RSACryptoServiceProvider());
            encnet.ExchangeRSAKeys();

            Console.WriteLine("[client]: Key exchange ok (foreign key: " + encnet.ForeignKey.ToByteArray().SHA1Hash().Hex().ToLower());
            Console.WriteLine("[client]: \t(us: " + encnet.LocalKey.ToByteArray().SHA1Hash().Hex().ToLower());

            encnet.SetEncrypted(EncryptionType.WRITE);
            Console.WriteLine("[client]: Write AES key ok");

            encnet.WriteValue<uint>(0xBEEFBEEF);
            Console.WriteLine("[client]: Write data ok");

            encnet.SetUnencrypted(EncryptionType.WRITE);

            encnet.SetEncrypted(EncryptionType.READ);
            Console.WriteLine("[client]: Read AES key ok");

            uint read = encnet.ReadValue<uint>();
            Console.WriteLine("[client]: Read data ok: 0x" + read.ToString("X"));

            encnet.SetUnencrypted(EncryptionType.READ);

            Console.WriteLine("[client]: Close");
            encnet.Close();
        }
        static void Main(string[] args)
        {
          /*  RSAPublicKey rp = RSAPublicKey.FromCSP(new System.Security.Cryptography.RSACryptoServiceProvider());

            Console.WriteLine(rp.mod.Length);
            Console.WriteLine(rp.exp.Length);
            Console.ReadLine();*/

            var serverThread = startThread(serv);
            var clientThread = startThread(clie);

            clientThread.Join();
            serverThread.Join();
            Console.ReadLine();
        }
        static Thread startThread(ThreadStart func)
        {
            Thread t = new Thread(func);
            t.Start();
            return t;
        }
    }
}
