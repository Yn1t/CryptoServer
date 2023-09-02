using System.Net.Sockets;
using System.Net;
using Benalo.classes;
using Benalo.interfaces;
using System.Numerics;
using Magenta;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Linq;
using filemanager;

namespace Server
{
    internal class CryptoServer
    {
        TcpListener listener;

        FileDecryptor decryptor = new FileDecryptor();
        FileEncryptor encryptor = new FileEncryptor();

        public CryptoServer(int port)
        {
            listener = new TcpListener(IPAddress.Any, port);
        }

        public async Task start()
        {
            listener.Start();

            Console.WriteLine("Server started...");

            while (true)
            {
                var tcpClient = await listener.AcceptTcpClientAsync();

                await Task.Run(async () => await ProcessClientAsync(tcpClient));
            }
        }


        // обрабатываем клиент
        async Task ProcessClientAsync(TcpClient tcpClient)
        {
            Console.WriteLine("New connection from " + tcpClient.Client.RemoteEndPoint.ToString());
            // Generate key 
            var block = new BigInteger(65537);
            var asymmetric = new Benalo.classes.AsymmetricEncryptionDecryption(block, Tests.SoloveyStrassen, 0.7, (ulong)block.GetByteCount() + 1);
            byte[]? sessionKey = new byte[]{};

            var stream = tcpClient.GetStream();
            using var binaryWriter = new BinaryWriter(stream);

            Key key = asymmetric.GetOnlyOpenKey();

            binaryWriter.Write("key");
            binaryWriter.Write(key.y.GetByteCount());
            binaryWriter.Write(key.y.ToByteArray());
            binaryWriter.Write(key.r.GetByteCount());
            binaryWriter.Write(key.r.ToByteArray());
            binaryWriter.Write(key.n.GetByteCount());
            binaryWriter.Write(key.n.ToByteArray());
            binaryWriter.Flush();

            while (true)
            {
                stream = tcpClient.GetStream();
                var binaryReader = new BinaryReader(stream);

                string type = binaryReader.ReadString();

                if (type == "file")
                {
                    string name = binaryReader.ReadString();
                    int size = (int)binaryReader.ReadInt64();
                    int padding = binaryReader.ReadInt32();

                    File.Delete("encrypted");
                    File.Delete(name);
                    FileStream f_in = new FileStream("encrypted", FileMode.Create);

                    for (int i = 0; i < size / 16; ++i)
                    {
                        byte[] bytes = binaryReader.ReadBytes(16);
                        f_in.Write(bytes);
                    }
                    f_in.Close();
                    
                    decryptor.Decrypt("encrypted", name, sessionKey, padding);
                    File.Delete("encrypted");
                    binaryWriter.Write("OK");

                    Console.WriteLine($"File {name} downloaded to server");
                }
                else if (type == "sessionKey")
                {
                    byte[] finalKey = new Byte[16];
                    Array.Fill<byte>(finalKey, 0);
                    for (int i = 0; i < 8; ++i)
                    {
                        int size = binaryReader.ReadInt32();
                        byte[] bytes = binaryReader.ReadBytes(size);
                        var temp = new BigInteger(bytes, true);
                        var bytesInt = asymmetric.Decryption(temp);
                        bytes = bytesInt.ToByteArray();
                        finalKey[i * 2] = bytes[0];
                        if (bytes.Length > 1)
                            finalKey[i * 2 + 1] = bytes[1];
                        else
                            finalKey[i * 2 + 1] = 0;
                    }
                    
                    sessionKey = finalKey;
                    Console.WriteLine("Session key exchange successfully ended");
                }
                else if (type == "down")
                {
                    string fileName = binaryReader.ReadString();

                    FileInfo fileInfo = new FileInfo(fileName);
                    if (fileInfo.Exists)
                    {
                        encryptor.Encrypt(fileName, "encrypted", sessionKey);
                        FileInfo encryptedInfo = new FileInfo("encrypted");
                        var size = encryptedInfo.Length;

                        binaryWriter.Write("file");
                        binaryWriter.Write(size);
                        binaryWriter.Write(encryptor.paddingCount);

                        FileStream f_in = new FileStream("encrypted", FileMode.Open);
                        for (int i = 0; i < size / 16; ++i)
                        {
                            byte[] bytes = new byte[16];
                            f_in.Read(bytes, 0, bytes.Length);
                            binaryWriter.Write(bytes);
                        }
                        f_in.Close();
                        File.Delete("encrypted");

                        if (!(binaryReader.ReadString() != "OK"))
                        {
                            break;
                        }
                    }
                    else
                    {
                        binaryWriter.Write("Dont");
                    }
                }
                else if (type == "end")
                {
                    break;
                }
            }

            Console.WriteLine("Closed connection from " + tcpClient.Client.RemoteEndPoint.ToString());
            tcpClient.Close();
        }

        internal void stop()
        {
            Console.WriteLine("Server stopped");
            listener?.Stop();
        }
    }
}
