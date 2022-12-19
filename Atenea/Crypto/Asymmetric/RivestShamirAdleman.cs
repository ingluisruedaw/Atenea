using Atenea.Resources;
using Atenea.Security;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace Atenea.Crypto.Asymmetric;

public class RivestShamirAdleman
{
    #region Constructor
    /// <summary>
    /// Constructor of the class <seealso cref="RivestShamirAdleman"/>.
    /// </summary>
    /// <param name="key"></param>
    [DebuggerStepThrough]
    public RivestShamirAdleman(string key, bool isEncode = false, bool doOAEPPadding = false) : this()
    {
        this.Key = key;
        this.IsEncode = isEncode;
        this.DoOAEPPadding = doOAEPPadding;
    }

    /// <summary>
    /// Constructor of the class <seealso cref="RivestShamirAdleman"/>.
    /// </summary>
    [DebuggerStepThrough]
    public RivestShamirAdleman()
    {
        this.Encodility = new Encod();
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
    /// Key Rsa private or public, depends encode or decode.
    /// </summary>
    public string Key { get; set; }

    /// <summary>
    /// Do OAE PPadding
    /// </summary>
    public bool DoOAEPPadding { get; set; }

    /// <summary>
    /// IsEncode is true if your use Encode otherwise false.
    /// </summary>
    public bool IsEncode { get; set; }
    #endregion

    #region Public
    /// <summary>
    /// RSA Encrypt Method.
    /// </summary>
    /// <param name="byteToEncrypt">Byte of data to Encrypt.</param>
    /// <returns>Encode Text Encrypt.</returns>
    /// <exception cref="ArgumentException">Validation to properties IsEncode.</exception>
    /// <exception cref="ArgumentNullException">Validation to properties Key.</exception>
    public string Encode(byte[] byteToEncrypt)
    {
        if (!this.IsEncode)
        {
            throw new ArgumentException(string.Format(Messages.MSG_E_A00000002, nameof(this.IsEncode), nameof(this.Decode)));
        }

        if (string.IsNullOrEmpty(this.Key) || string.IsNullOrWhiteSpace(this.Key))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(this.Key)));
        }

        return this.Run(byteToEncrypt);
    }

    /// <summary>
    /// RSA Encrypt Method.
    /// </summary>
    /// <param name="textToEncrypt">Text to Encrypt.</param>
    /// <returns>Encode Text Encrypt.</returns>
    /// <exception cref="ArgumentNullException">Validation parameter textToEncrypt.</exception>
    public string Encode(string textToEncrypt)
    {
        if (string.IsNullOrEmpty(textToEncrypt) || string.IsNullOrWhiteSpace(textToEncrypt))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(textToEncrypt)));
        }

        return Encode(Encodility.Encode(textToEncrypt));
    }

    /// <summary>
    /// RSA Decrypt.
    /// </summary>
    /// <param name="byteToDecrypt">Byte of data to Decrypt.</param>
    /// <returns>Text Decrypt.</returns>
    /// <exception cref="ArgumentException">Validation to properties IsEncode.</exception>
    public string Decode(byte[] byteToDecrypt)
    {
        if (this.IsEncode)
        {
            throw new ArgumentException(string.Format(Messages.MSG_E_A00000002, nameof(this.IsEncode), nameof(this.Encode)));
        }

        return this.Run(byteToDecrypt);
    }

    /// <summary>
    /// RSA Decrypt.
    /// </summary>
    /// <param name="stringToDecrypt">Text to Decrypt.</param>
    /// <returns>Text Decrypt.</returns>
    /// <exception cref="ArgumentNullException">Validation parameter stringToDecrypt.</exception>
    public string Decode(string stringToDecrypt)
    {
        if (string.IsNullOrEmpty(stringToDecrypt) || string.IsNullOrWhiteSpace(stringToDecrypt))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(stringToDecrypt)));
        }

        return Decode(Encodility.Decode(stringToDecrypt));
    }

    /// <summary>
    /// Generating Keys
    /// </summary>
    /// <param name="keySize">key size.</param>
    /// <returns>array keys.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public string[] Generate(int keySize)
    {
        if (keySize <= default(int))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(keySize)));
        }

        var rSACryptoServiceProvider = new RSACryptoServiceProvider(keySize);
        var privKey = rSACryptoServiceProvider.ExportParameters(true);
        var pubKey = rSACryptoServiceProvider.ExportParameters(false);
        string pubKeyString = this.GetKeyString(pubKey);
        string privKeyString = this.GetKeyString(privKey);
        return new string[] { privKeyString, pubKeyString };
    }
    #endregion

    #region Private
    /// <summary>
    /// Encode and Decode Rivest Shamir Adleman.
    /// </summary>
    /// <param name="crypto"></param>
    /// <returns>Encode or Decode byte Text.</returns>
    private string Run(byte[] crypto)
    {
        try
        {
            string text = null;
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(this.GetRSAParameters(this.Key));
                text = this.IsEncode
                    ? this.Encodility.Encode(rsa.Encrypt(crypto, this.DoOAEPPadding))
                    : this.Encodility.Decode(rsa.Decrypt(crypto, this.DoOAEPPadding));
            }

            return text;
        }
        catch (Exception e)
        {
            throw e;
        }
    }

    /// <summary>
    /// Get RSA Parameters.
    /// </summary>
    /// <param name="key">Key serialize</param>
    /// <returns>Object type <seealso cref="RSAParameters"/>.</returns>
    /// <exception cref="ArgumentNullException">Validation parameter key.</exception>
    private RSAParameters GetRSAParameters(string key)
    {
        if (string.IsNullOrEmpty(key) || string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(key)));
        }

        RSAParameters rsa = default(RSAParameters);
        XmlSerializer ser = new XmlSerializer(typeof(RSAParameters));
        StringReader KeyInfo = new StringReader(key);
        var serialize = ser.Deserialize(KeyInfo);
        if (serialize != null)
        {
            rsa = (RSAParameters)serialize;
        }

        return rsa;
    }

    /// <summary>
    /// Get Key String
    /// </summary>
    /// <param name="key">Object to serialize.</param>
    /// <returns>serialize to string.</returns>
    private string GetKeyString(RSAParameters key)
    {
        var stringWriter = new StringWriter();
        var xmlSerializer = new XmlSerializer(typeof(RSAParameters));
        xmlSerializer.Serialize(stringWriter, key);
        return stringWriter.ToString();
    }
    #endregion
}
