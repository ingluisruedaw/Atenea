using System.Diagnostics;
using System.Text;

namespace Atenea.Security;

internal class Encod
{
    [DebuggerStepThrough]
    internal byte[] Encode(string text) => Encoding.Unicode.GetBytes(text);

    [DebuggerStepThrough]
    internal string Encode(byte[] text) => Convert.ToBase64String(text);

    [DebuggerStepThrough]
    internal string Decode(byte[] text) => Encoding.Unicode.GetString(text);

    [DebuggerStepThrough]
    internal byte[] Decode(string text) => Convert.FromBase64String(text);

    [DebuggerStepThrough]
    internal byte[] EncodeASCII(string text) => Encoding.ASCII.GetBytes(text);

    [DebuggerStepThrough]
    internal string DecodeToHexString(byte[] hashBytes) => Convert.ToHexString(hashBytes);
}
