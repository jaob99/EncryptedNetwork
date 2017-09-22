using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

using NetworkTools.Tools;

namespace NetworkTools
{
    /// <summary>
    /// Provides a wrapper to override methods of a Stream
    /// </summary>
    public abstract class BackedStream : Stream
    {
        protected Stream backing;
        /// <summary>
        /// The Stream used as the backing
        /// </summary>
        public Stream @Stream { get { return backing; } }
        /// <summary>
        /// Keep the backing stream alive after the class is disposed (default <c>false</c>)
        /// </summary>
        public bool KeepBackingStreamAlive { get; set; }
        /// <summary>
        /// Initialise an instance of the BackedStream class
        /// </summary>
        /// <param name="s">The initial Stream</param>
        public BackedStream(Stream s)
        {
            backing = s;
            KeepBackingStreamAlive = false;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if(!KeepBackingStreamAlive) backing.Dispose();
            }
        }

        #region Stream Overrides
        public override bool CanRead
        {
            get { return Stream.CanRead; }
        }
        public override bool CanSeek
        {
            get { return Stream.CanSeek; }
        }
        public override bool CanWrite
        {
            get { return Stream.CanWrite; }
        }
        public override void Flush()
        {
            Stream.Flush();
        }
        public override long Length
        {
            get { return Stream.Length; }
        }
        public override long Position
        {
            get
            {
                return Stream.Position;
            }
            set
            {
                Stream.Position = value;
            }
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            return Stream.Seek(offset, origin);
        }
        public override void SetLength(long value)
        {
            Stream.SetLength(value);
        }
        #endregion
    }
    /// <summary>
    /// Provides a wrapper to override methods of a NetworkStream
    /// </summary>
    public abstract class BackedNetworkStream : BackedStream
    {
        /// <summary>
        /// Initialise an instance of the BackedNetworkStream class
        /// </summary>
        /// <param name="stream">The initial NetworkStream</param>
        public BackedNetworkStream(NetworkStream stream) : base(stream) { }
        /// <summary>
        /// Initialise an instance of the BackedNetworkStream class
        /// </summary>
        /// <param name="sock">The Socket to derive the backing NetworkStream from</param>
        public BackedNetworkStream(Socket sock) : this(new NetworkStream(sock)) { }

        /// <summary>
        /// The backing NetworkStream of this instance
        /// </summary>
        public new NetworkStream Stream { get { return backing as NetworkStream; } }

    }
    
    namespace EncryptedNetwork
    {
        /// <summary>
        /// Provides a mehtod of sending encrypted data over a NetworkStream or Socket
        /// </summary>
        /// <remarks>Uses RSA/ECB/PKCS1Padding algorithm as well as AES/CBC/PKCS5Padding for encryption, CRC32 for checksum computation</remarks>
        public class EncryptedNetworkStream : BackedNetworkStream
        {
            /// <summary>
            /// Remote endpoint RSA public key
            /// </summary>
            public RSAPublicKey ForeignKey { get { return RSAPublicKey.FromCSP(rsa_foreign); } }

            /// <summary>
            /// Our RSA public key
            /// </summary>
            public RSAPublicKey LocalKey { get { return RSAPublicKey.FromCSP(rsa_local); } }


            private RSACryptoServiceProvider rsa_local;
            private RSACryptoServiceProvider rsa_foreign;

            private AesCryptoServiceProvider read_encrypt = null;
            private AesCryptoServiceProvider write_encrypt = null;

            private ICryptoTransform trans_cur_r = null;
            private ICryptoTransform trans_cur_w = null;

            /// <summary>
            /// Is the Stream currently set to decrypt read data
            /// </summary>
            public bool IsEncryptedRead { get { return read_encrypt != null; } }
            /// <summary>
            /// Is the Stream currently set to encrypt written data
            /// </summary>
            public bool IsEncryptedWrite { get { return write_encrypt != null; } }

            private long _data_read = 0;
            private long _data_written = 0;

            private bool _log_data = false;

            /// <summary>
            /// When set to <c>true</c>, read/write requests will log the number of encrypted bytes read/written
            /// </summary>
            /// <seealso cref="GetEncryptedDataReadAndReset()"/>
            /// <seealso cref="GetEncryptedDataWrittenAndReset()"/>
            public bool EnableEncryptedDataLogging { get { return _log_data; } set { _log_data = value; } }

            /// <summary>
            /// If <code>EnableEncryptedDataLogging</code> is set to <c>true</c>, returns the number of read bytes logged and then resets the internal counter to 0
            /// </summary>
            /// <seealso cref="EnableEncryptedDataLogging"/>
            public long GetEncryptedDataReadAndReset()
            {
                long r = _data_read;
                _data_read = 0;
                return r;
            }
            /// <summary>
            /// If <code>EnableEncryptedDataLogging</code> is set to <c>true</c>, returns the number of written bytes logged and then resets the internal counter to 0
            /// </summary>
            /// <seealso cref="EnableEncryptedDataLogging"/>
            public long GetEncryptedDataWrittenAndReset()
            {
                long r = _data_written;
                _data_written = 0;
                return r;
            }
           

            /// <summary>
            /// Set to true to keep the RSACryptoServiceProveder alive after the Stream is disposed
            /// </summary>
            public bool RSAKeepAlive { get; set; }
            
            /// <summary>
            /// Initialise a new instance of the EncryptedNetworkStream class from a Socket
            /// </summary>
            /// <param name="sock">The Socket to use as backing</param>
            /// <param name="rsa">The RSACryptoServiceProvider to use to encrypt</param>
            public EncryptedNetworkStream(Socket sock, RSACryptoServiceProvider rsa) : this(new NetworkStream(sock),rsa) { }
            /// <summary>
            /// Initialise a new instance of the EncryptedNetworkStream class from a NetworkStream
            /// </summary>
            /// <param name="stream">The NetworkStream to use as backing</param>
            /// <param name="rsa">The RSACryptoServiceProvider to use to encrypt</param>
            public EncryptedNetworkStream(NetworkStream stream, RSACryptoServiceProvider rsa)
                : base(stream)
            {
                rsa_local = rsa;
                rsa_foreign = new RSACryptoServiceProvider();
                RSAKeepAlive = false;
               // Console.WriteLine(rsa_local.KeySize);
            }

            /// <summary>
            /// Exchange the RSA public keys of each endpoint
            /// </summary>
            public void ExchangeRSAKeys()
            {
                var us = RSAPublicKey.FromCSP(rsa_local);
                uint checksum = DamienG.Security.Cryptography.Crc32.Compute(us);

                backing.WriteAll(us);
                backing.WriteValue<uint>(checksum);

                byte[] buffer =  backing.ReadNew(Marshal.SizeOf(typeof(RSAPublicKey)));
                uint for_checksum = backing.ReadValue<uint>();

                if (DamienG.Security.Cryptography.Crc32.Compute(buffer) != for_checksum)
                    throw new InvalidDataException("Data recieved had an invalid checksum");
                else
                {
                    RSAPublicKey rpk = (RSAPublicKey)buffer;
                    rpk.ToCSP(rsa_foreign);
                }
            }

            /// <summary>
            /// Set stream data written/read to encrypted
            /// </summary>
            /// <param name="type">On read/on write/both</param>
            public void SetEncrypted(EncryptionType type)
            {
                if (type == EncryptionType.BOTH)
                {
                    SetEncryptedWrite();
                    SetEncryptedRead();
                }
                else if (type == EncryptionType.READ) SetEncryptedRead();
                else if (type == EncryptionType.WRITE) SetEncryptedWrite();
            }

            /// <summary>
            /// Set stream data written/read to unencrypted
            /// </summary>
            /// <param name="type">On read/on write/both</param>
            public void SetUnencrypted(EncryptionType type)
            {
                if (type == EncryptionType.BOTH)
                {
                    UnsetEncryptedWrite();
                    UnsetEncryptedRead();
                }
                else if (type == EncryptionType.READ) UnsetEncryptedRead();
                else if (type == EncryptionType.WRITE) UnsetEncryptedWrite();
            }

            /// <summary>
            /// Begin encrypting written data
            /// </summary>
            public void SetEncryptedWrite()
            {
                write_encrypt = new AesCryptoServiceProvider();
                AESKey key = AESKey.NewKey();
                key.ToCSP(write_encrypt);
                
                trans_cur_w = write_encrypt.CreateEncryptor();
                
                byte[] ekey = rsa_foreign.Encrypt(key.ToByteArray(), false);
                backing.WriteValue<int>(ekey.Length);
                backing.WriteAll(ekey);
                backing.WriteValue<uint>(DamienG.Security.Cryptography.Crc32.Compute(ekey));
            }
            /// <summary>
            /// Begin decrypting read data
            /// </summary>
            public void SetEncryptedRead()
            {
                byte[] value = backing.ReadNew(backing.ReadValue<int>());
                uint rec_checksum = backing.ReadValue<uint>();
                uint checksum = DamienG.Security.Cryptography.Crc32.Compute(value);
                if (rec_checksum != checksum)
                {
                    throw new InvalidDataException("Bad data recieved from stream (checksum recieved was [0x" + rec_checksum.ToString("X") + "], checksum was [0x" + checksum.ToString("X") + "] for the data recieved)");
                }
                else
                {
                    read_encrypt = new AesCryptoServiceProvider();
                    var key = rsa_local.Decrypt(value, false).ToStructure<AESKey>();
                    key.ToCSP(read_encrypt);
                    
                    trans_cur_r = read_encrypt.CreateDecryptor();
                }
            }

            /// <summary>
            /// Set write mode to unencrypted
            /// </summary>
            public void UnsetEncryptedWrite()
            {
                trans_cur_w.Dispose();
                write_encrypt.Dispose();
                write_encrypt = null;
                trans_cur_w = null;
            }
            /// <summary>
            /// Set read mode to unencrypted
            /// </summary>
            public void UnsetEncryptedRead()
            {
                trans_cur_r.Dispose();
                read_encrypt.Dispose();
                read_encrypt = null;
                trans_cur_r = null;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (IsEncryptedRead)
                {
                    byte[] byr = new byte[count%16==0?count+16:roundUp(count, 16)];
                    
                    int s = backing.Read(byr, 0, byr.Length);
                    while (s < byr.Length)
                    {
                        s += backing.Read(byr, s, byr.Length - s);
                    }


                    byte[] data_dec = trans_cur_r.TransformFinalBlock(byr, 0, byr.Length);
                    Array.Copy(data_dec, 0, buffer, offset, count);

                    trans_cur_r.Dispose();
                    trans_cur_r = read_encrypt.CreateDecryptor();

                    if (_log_data) _data_read += data_dec.Length;

                    return data_dec.Length;
                }
                else return backing.Read(buffer, offset, count);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (IsEncryptedWrite)
                {
                    byte[] data = trans_cur_w.TransformFinalBlock(buffer, offset, count);
                    backing.Write(data, 0, data.Length);

                    if (_log_data) _data_written += data.Length;
                }
                else backing.Write(buffer, offset, count);
            }

            private static int roundUp(int numToRound, int multiple)
            {
                if (multiple == 0)
                    return numToRound;

                int remainder = Math.Abs(numToRound) % multiple;
                if (remainder == 0)
                    return numToRound;
                if (numToRound < 0)
                    return -(Math.Abs(numToRound) - remainder);
                return numToRound + multiple - remainder;
            }

            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                if (disposing)
                {
                    if(!RSAKeepAlive) rsa_local.Dispose();
                    rsa_foreign.Dispose();
                    if (trans_cur_r != null) trans_cur_r.Dispose();
                    if (trans_cur_w != null) trans_cur_w.Dispose();
                    if (write_encrypt != null) write_encrypt.Dispose();
                    if (read_encrypt != null) read_encrypt.Dispose();
                }
            }

            /// <summary>
            /// Write a string with the specified encoding to the stream
            /// </summary>
            /// <param name="str"></param>
            /// <param name="enc"></param>
            /// <remarks>The length of the string is written and the CodePage of the encoding is written before as 32bit signed integers</remarks>
            public void WriteString(string str, Encoding enc)
            {
                byte[] data = enc.GetBytes(str);
                this.WriteValue<int>(data.Length);
                this.WriteValue<int>(enc.CodePage);
                this.WriteAll(data);
            }
            /// <summary>
            /// Read a string with the specified encoding
            /// </summary>
            /// <param name="enc">The encoding used to decode the data, set to null to use the encoding recieved</param>
            /// <returns>The read string</returns>
            public string ReadString(Encoding enc)
            {
                int len = this.ReadValue<int>();
                int cp = this.ReadValue<int>();
                byte[] data = this.ReadNew(len);
                if (enc == null)
                {
                    return Encoding.GetEncoding(cp).GetString(data);
                }
                else return enc.GetString(data);
            }

            /// <summary>
            /// Write a string with the default ASCII encoding
            /// </summary>
            /// <param name="str">The string to write</param>
            public void WriteString(string str)
            {
                WriteString(str, Encoding.ASCII);
            }
            /// <summary>
            /// Read a string with the recieved encoding
            /// </summary>
            /// <returns>The read string</returns>
            public string ReadString()
            {
                return ReadString(null);
            }

        }
        public enum EncryptionType
        {
            READ,WRITE,BOTH
        }
        /// <summary>
        /// Holds data for an AES key
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct AESKey
        {
            /// <summary>
            /// The Key (256 bit)
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U1, SizeConst = 32)]
            public byte[] key;
            /// <summary>
            /// The IV (128)
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U1, SizeConst = 16)]
            public byte[] iv;
            
            /// <summary>
            /// Create a new key
            /// </summary>
            /// <returns>The new AES Key</returns>
            public static AESKey NewKey()
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                AESKey k = new AESKey();
                k.key = new byte[32];
                k.iv = new byte[16];

                rng.GetBytes(k.key);
                rng.GetBytes(k.iv);
                rng.Dispose();
                return k;
            }
            /// <summary>
            /// Set the key and iv to an AesCryptoServiceProvider
            /// </summary>
            /// <param name="r">The CSP</param>
            public void ToCSP(AesCryptoServiceProvider r)
            {
                r.KeySize = 256;
                r.BlockSize = 128;

                r.Key = key;
                r.IV = iv;
            }
        }
        /// <summary>
        /// Holds RSA public key data (modulus and exponent)
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct RSAPublicKey
        {
            /// <summary>
            /// The modulus of this key
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType= UnmanagedType.U1, SizeConst = 128)]
            public byte[] mod;

            /// <summary>
            /// The public exponent of this key
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U1, SizeConst = 3)]
            public byte[] exp;

            /// <summary>
            /// Binary serialisation of this key
            /// </summary>
            [Obsolete("Use Marshal instead")]
            public byte[] BinaryData
            {
                get
                {
                    return this.ToByteArray();
                }
                set
                {
                    RSAPublicKey im = value.ToStructure<RSAPublicKey>();

                    mod = im.mod;
                    exp = im.exp;
                }
            }

            /// <summary>
            /// Set the public key to a RSACryptoServiceProvider
            /// </summary>
            /// <param name="csp">The CSP to set the key to</param>
            public void ToCSP(RSACryptoServiceProvider csp)
            {
                var p = csp.ExportParameters(false);
                p.Modulus = mod;
                p.Exponent = exp;
                csp.ImportParameters(p);
            }
            /// <summary>
            /// Get the public key information from an RSACryptoServiceProvider and return it in an RSAPublicKey struct
            /// </summary>
            /// <param name="csp">The CSP</param>
            /// <returns>A new RSAPublicKey struct</returns>
            public static RSAPublicKey FromCSP(RSACryptoServiceProvider csp)
            {
                RSAPublicKey rp = new RSAPublicKey();
                var p = csp.ExportParameters(false);
                rp.mod = p.Modulus;
                rp.exp = p.Exponent;
                return rp;
            }

            public static implicit operator byte[](RSAPublicKey rp)
            {
                return rp.ToByteArray();
            }
            public static explicit operator RSAPublicKey(byte[] byt)
            {
                return byt.ToStructure<RSAPublicKey>();
            }
        }
    }
}
