using Atenea.Resources;
using Atenea.Security;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Atenea.Crypto.Symmetric;

/// <summary>
/// Class of type <seealso cref="AdvancesEncryptionStandard"/>
/// </summary>
public class AdvancesEncryptionStandard
{
    #region Constructor
    /// <summary>
    /// Constructor of class <seealso cref="AdvancesEncryptionStandard"/>.
    /// </summary>
    /// <param name="keySecurityPass">key Security Pass.</param>
    /// <param name="keySaltBytes">key Salt Bytes.</param>
    /// <exception cref="ArgumentNullException"></exception>
    [DebuggerStepThrough]
    public AdvancesEncryptionStandard(string keySecurityPass, string keySaltBytes)
    {
        this.Encodility = new Encod();
        this.Initialize(keySecurityPass, keySaltBytes);
    }

    /// <summary>
    /// Constructor of class <seealso cref="AdvancesEncryptionStandard"/>.
    /// </summary>
    [DebuggerStepThrough]
    public AdvancesEncryptionStandard(){
        using (Aes myAes = Aes.Create())
        {
            this.Encodility = new Encod();
            this.Initialize(this.Encodility.Encode(myAes.Key), this.Encodility.Encode(myAes.IV));
        }
    }
    #endregion

    #region Variables
    /// <summary>
    /// Class of type <seealso cref="Encod"/>.
    /// </summary>
    private Encod Encodility;
    #endregion

    #region Properties
    /// <summary>
    /// Key Security Pass.
    /// </summary>
    private byte[] KeySecurityPass { get; set; }

    /// <summary>
    /// Key Salt Bytes.
    /// </summary>
    private byte[] KeySaltBytes { get; set; }
    #endregion

    #region Public
    /// <summary>
    /// Encode Input Text.
    /// </summary>
    /// <param name="input">Input Text.</param>
    /// <returns>Encode Text.</returns>
    [DebuggerStepThrough]
    public string Encode(string input)
    {
        return this.Run(input, null);
    }

    /// <summary>
    /// Decode Encode Text.
    /// </summary>
    /// <param name="input">Input Encode Text.</param>
    /// <returns>Decode Text.</returns>
    [DebuggerStepThrough]
    public string Decode(string input)
    {
        return this.Run(null, Encodility.Decode(input));
    }

    /// <summary>
    /// Decode Encode Text.
    /// </summary>
    /// <param name="input">Input Encode Byte Text.</param>
    /// <returns>Decode Text.</returns>
    [DebuggerStepThrough]
    public string Decode(byte[] input)
    {
        return this.Run(null, input);
    }
    #endregion

    #region Private
    /// <summary>
    /// Initialize objects and properties.
    /// </summary>
    /// <param name="keySecurityPass">key Security Pass.</param>
    /// <param name="keySaltBytes">key Salt Bytes.</param>
    /// <exception cref="ArgumentNullException">Validation null or empty.</exception>
    private void Initialize(string keySecurityPass, string keySaltBytes)
    {
        if (string.IsNullOrEmpty(keySecurityPass) || string.IsNullOrWhiteSpace(keySecurityPass))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(keySecurityPass)));
        }

        if (string.IsNullOrEmpty(keySaltBytes) || string.IsNullOrWhiteSpace(keySaltBytes))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(keySaltBytes)));
        }
        
        this.KeySecurityPass = Encodility.Decode(keySecurityPass);
        this.KeySaltBytes = Encodility.Decode(keySaltBytes);
    }

    /// <summary>
    /// Encode and Decode Advances Encryption Standard.
    /// </summary>
    /// <param name="encode">Encode Text.</param>
    /// <param name="decode">Decode Text.</param>
    /// <returns>Encode or Decode Text.</returns>
    [DebuggerStepThrough]
    private string Run(string encode, byte[] decode)
    {
        try
        {
            bool isEncode = !string.IsNullOrEmpty(encode);
            string text;

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = this.KeySecurityPass;
                aesAlg.IV = this.KeySaltBytes;

                ICryptoTransform crypto = isEncode ?
                    aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV) :
                    aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msEncrypt = isEncode ? new MemoryStream() : new MemoryStream(decode))
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, crypto, isEncode ? CryptoStreamMode.Write : CryptoStreamMode.Read))
                    {
                        if (isEncode)
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(encode);
                            }

                            text = Encodility.Encode(msEncrypt.ToArray());
                        }
                        else
                        {
                            using (var srDecrypt = new StreamReader(csEncrypt))
                            {
                                text = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }

            return text;
        }
        catch (Exception e)
        {
            throw e;
        }
        
    }
    #endregion
}
