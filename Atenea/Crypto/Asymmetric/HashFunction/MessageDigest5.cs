using Atenea.Resources;
using Atenea.Security;
using System.Diagnostics;

namespace Atenea.Crypto.Asymmetric.HashFunction;

public class MessageDigest5
{
    #region Constructor
    /// <summary>
    /// Constructor of the class <seealso cref="Md5"/>.
    /// </summary>
    [DebuggerStepThrough]
    public MessageDigest5() 
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

    #region Public
    /// <summary>
    /// MD5 Encrypt.
    /// </summary>
    /// <param name="input">Text to Encode.</param>
    /// <returns>Encode Text</returns>
    [DebuggerStepThrough]
    public string Encode(string input)
    {
        try
        {
            if (string.IsNullOrEmpty(input) || string.IsNullOrWhiteSpace(input))
            {
                throw new ArgumentNullException(string.Format(Messages.MSG_E_A00000001, nameof(input)));
            }

            string hash = null;
            using (var x = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = Encodility.EncodeASCII(input);
                byte[] hashBytes = x.ComputeHash(inputBytes);
                hash = Encodility.DecodeToHexString(hashBytes);
            }

            return hash;
        }
        catch (Exception ex)
        {
            throw ex;
        }
    }
    #endregion
}
