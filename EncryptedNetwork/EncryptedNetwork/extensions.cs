using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NetworkTools.Tools
{
    
    namespace ByValStrings
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString1
        {
            public ByValANSIString1(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1)]
            public string cstring;
            public static implicit operator ByValANSIString1(string s)
            {
                return new ByValANSIString1(s);
            }
            public static explicit operator string(ByValANSIString1 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString2
        {
            public ByValANSIString2(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2)]
            public string cstring;
            public static implicit operator ByValANSIString2(string s)
            {
                return new ByValANSIString2(s);
            }
            public static explicit operator string(ByValANSIString2 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString4
        {
            public ByValANSIString4(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4)]
            public string cstring;
            public static implicit operator ByValANSIString4(string s)
            {
                return new ByValANSIString4(s);
            }
            public static explicit operator string(ByValANSIString4 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString8
        {
            public ByValANSIString8(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string cstring;
            public static implicit operator ByValANSIString8(string s)
            {
                return new ByValANSIString8(s);
            }
            public static explicit operator string(ByValANSIString8 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString16
        {
            public ByValANSIString16(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string cstring;
            public static implicit operator ByValANSIString16(string s)
            {
                return new ByValANSIString16(s);
            }
            public static explicit operator string(ByValANSIString16 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString32
        {
            public ByValANSIString32(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string cstring;
            public static implicit operator ByValANSIString32(string s)
            {
                return new ByValANSIString32(s);
            }
            public static explicit operator string(ByValANSIString32 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString64
        {
            public ByValANSIString64(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string cstring;
            public static implicit operator ByValANSIString64(string s)
            {
                return new ByValANSIString64(s);
            }
            public static explicit operator string(ByValANSIString64 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString128
        {
            public ByValANSIString128(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string cstring;
            public static implicit operator ByValANSIString128(string s)
            {
                return new ByValANSIString128(s);
            }
            public static explicit operator string(ByValANSIString128 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString256
        {
            public ByValANSIString256(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string cstring;
            public static implicit operator ByValANSIString256(string s)
            {
                return new ByValANSIString256(s);
            }
            public static explicit operator string(ByValANSIString256 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString1024
        {
            public ByValANSIString1024(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
            public string cstring;
            public static implicit operator ByValANSIString1024(string s)
            {
                return new ByValANSIString1024(s);
            }
            public static explicit operator string(ByValANSIString1024 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString2048
        {
            public ByValANSIString2048(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2048)]
            public string cstring;
            public static implicit operator ByValANSIString2048(string s)
            {
                return new ByValANSIString2048(s);
            }
            public static explicit operator string(ByValANSIString2048 s)
            {
                return s.cstring;
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct ByValANSIString4096
        {
            public ByValANSIString4096(string c)
            {
                cstring = c;
            }
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4096)]
            public string cstring;
            public static implicit operator ByValANSIString4096(string s)
            {
                return new ByValANSIString4096(s);
            }
            public static explicit operator string(ByValANSIString4096 s)
            {
                return s.cstring;
            }
        }
    }
    public static class Extensions
    {
        public static ArrayBuilder<byte> Append<S>(this ArrayBuilder<byte> t, S structure) where S : struct
        {
            return t.Append(structure.ToByteArray());
        }
        public static ArrayBuilder<byte> Append(this ArrayBuilder<byte> t, object structure)
        {
            if (structure.GetType().IsValueType)
            {
                int size = Marshal.SizeOf(structure.GetType());
                byte[] buf = new byte[size];
                using (GCHPinned gcp = new GCHPinned(buf))
                {
                    Marshal.StructureToPtr(structure, gcp, true);
                }
                return t.Append(buf);
            }
            else throw new ArgumentException("Argument must be a structure");
        }
   
        public static IEnumerable<T> ConcatAll<T>(this IEnumerable<T[]> t)
        {
            foreach (T[] tt in t)
            {
                for (int i = 0; i < tt.Length; i++) yield return tt[i];
            }
        }
        public static byte[] SHA1Hash(this byte[] by)
        {
            SHA1 sh = SHA1.Create();
            byte[] ret = sh.ComputeHash(by);
            sh.Dispose();
            return ret;
        }
        public static T[] SingleArray<T>(this T t)
        {
            return new T[] { t };
        }
        public static T[] Pad<T>(this T[] t, int l)
        {
            T[] ret = new T[l];
            for (int i = 0; i < t.Length && i < l; i++)
                ret[i] = t[i];
            return ret;
        }
        public static bool ValueExists(this Microsoft.Win32.RegistryKey @this, string name)
        {
            return @this.GetValue(name) != null;
        }
        public static bool SubkeyExists(this Microsoft.Win32.RegistryKey @this, string name)
        {
            var v =  @this.OpenSubKey(name);
            if (v == null) return false;
            else
            {
                v.Close();
                return true;
            }
        }
        public static byte[] ToByteArray<T>(this T t) where T : struct
        {
            int sz = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[sz];
            var h = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            Marshal.StructureToPtr(t, h.AddrOfPinnedObject(), true);
            h.Free();
            return buffer;
        }
        public static T ToStructure<T>(this byte[] bytes) where T : struct
        {
            return bytes.ToStructure<T>(0);
        }
        public static T ToStructure<T>(this byte[] bytes, int offset) where T : struct
        {
            T val;
            int sz = Marshal.SizeOf(typeof(T));
            var h = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            val = (T)Marshal.PtrToStructure(h.AddrOfPinnedObject() + (sizeof(byte) * offset), typeof(T));
            h.Free();
            return val;
        }
        public static void WriteValue<T>(this Stream s, T t) where T : struct
        {
            byte[] b = t.ToByteArray();
            s.Write(b, 0, b.Length);
        }
        public static byte[] ReadNew(this Stream s, int len)
        {
            byte[] r = new byte[len];
            s.Read(r, 0, len);
            return r;
        }
        public static T[] PadWith<T>(this T[] t, int len, Func<int, T> selector)
        {
            return Enumerable.Range(0, len).Select(x => x >= t.Length ? selector(x) : t[x]).ToArray();
        }
        public static byte[] EncodeToByteArray(this string s, Encoding e)
        {
            return e.GetBytes(s);
        }
        public static byte[] EncodeToByteArray(this string s)
        {
            return s.EncodeToByteArray(Encoding.ASCII);
        }
        public static string DecodeToString(this byte[] byt, Encoding e)
        {
            return e.GetString(byt);
        }
        public static string DecodeToString(this byte[] byt)
        {
            return byt.DecodeToString(Encoding.ASCII);
        }
        public static bool ElementsEqual<T>(this T[] ar, T[] o, int len)
        {
            return ar.ElementsEqual(o, 0, len);
        }
        public static bool ElementsEqual<T>(this T[] ar, T[] o, int offset, int len)
        {
            return ar.ElementsEqual(o, offset, offset, len);
        }
        public static T[] SubArray<T>(this T[] ar, int index)
        {
            return ar.SubArray(index, ar.Length - index);
        }
        public static T[] SubArray<T>(this T[] ar, int index, int length)
        {
            T[] ret = new T[length];
            for (int i = 0; i < length; i++) ret[i] = ar[index + i];
            return ret;
        }
        public static bool ElementsEqual<T>(this T[] ar, T[] o, int of1, int of2, int len)
        {
            for (int i = 0; i < len; i++)
                if (!ar[of1 + i].Equals(o[of2 + i])) return false;
            return true;
        }
        public static T ReadValue<T>(this Stream s) where T : struct
        {
            int sz = Marshal.SizeOf(typeof(T));
            byte[] buf = s.ReadNew(sz);
            return buf.ToStructure<T>();
        }
        public static void WriteAll(this Stream s, byte[] by)
        {
            s.Write(by, 0, by.Length);
        }
        public static int ReadAll(this Stream s, byte[] by)
        {
           return  s.Read(by, 0, by.Length);
        }
        public static string Hex(this byte[] byt)
        {
            return BitConverter.ToString(byt).Replace("-", "");
        }
        public static byte[] UnHex(this string s)
        {
            return Enumerable.Range(0, s.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(s.Substring(x, 2)))
                             .ToArray();
        }
    }
    public class GCHPinned : IDisposable
    {
        private GCHandle handle;
        public IntPtr Pointer { get { return handle.AddrOfPinnedObject(); } }
        public GCHPinned(GCHandle h)
        {
            handle = h;
        }
        public GCHPinned(object o) : this(GCHandle.Alloc(o, GCHandleType.Pinned)) { }

        public void Dispose()
        {
            handle.Free();
        }

        public static implicit operator IntPtr(GCHPinned p)
        {
            return p.Pointer;
        }
    }
    public class ArrayBuilder<T>
    {
        private List<T[]> list;
        public ArrayBuilder()
        {
            list = new List<T[]>();
        }
        public ArrayBuilder<T> Append(T[] ar)
        {
            list.Add(ar);
            return this;
        }
        public ArrayBuilder<T> Append(T[][] arar)
        {
            list.Add(arar.ConcatAll().ToArray());
            return this;
        }
        public ArrayBuilder<T> Append(T single)
        {
            list.Add(new T[] { single });
            return this;
        }
        public T[] ToArray()
        {
            return list.ToArray().ConcatAll().ToArray();
        }
        public override bool Equals(object obj)
        {
            if (obj is ArrayBuilder<T>)
            {
                if (Length == (obj as ArrayBuilder<T>).Length) return ToArray().ElementsEqual((obj as ArrayBuilder<T>).ToArray(), Length);

            }
            else if (obj is T[])
            {
                if (Length == (obj as T[]).Length) return ToArray().ElementsEqual((obj as T[]), Length);
            }
            return obj.Equals(this);
        }
        public override int GetHashCode()
        {
            return ToArray().GetHashCode();
        }

        public int Length
        {
            get
            {
                return list.Select(x => x.Length).Sum();
            }
        }
    }
}
