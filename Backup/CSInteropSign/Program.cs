using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace CSInteropSign
{
  class Program
  {
    internal static void Main(string[] args)
    {
      CreateDsaKeys();

      SignDsaMessage();

      VerifyDsaMessage();
    }

    private static void VerifyDsaMessage()
    {
      //
      // Load the Public Key
      //   X.509 Format
      //
      AsnKeyParser keyParser =
        new AsnKeyParser("public.dsa.cs.key");

      DSAParameters publicKey = keyParser.ParseDSAPublicKey();

      //
      // Initailize the CSP
      //
      CspParameters csp = new CspParameters();

      // Cannot use PROV_DSS_DH
      const int PROV_DSS = 3;
      csp.ProviderType = PROV_DSS;

      const int AT_SIGNATURE = 2;
      csp.KeyNumber = AT_SIGNATURE;

      csp.KeyContainerName = "DSA Test (OK to Delete)";

      //
      // Initialize the Provider
      //
      DSACryptoServiceProvider dsa =
        new DSACryptoServiceProvider(csp);
      dsa.PersistKeyInCsp = false;

      //
      // The moment of truth...
      //
      dsa.ImportParameters(publicKey);

      //
      // Load the message
      //   Message is m
      //
      byte[] message = null;
      using (BinaryReader reader = new BinaryReader(
          new FileStream("dsa.cs.msg", FileMode.Open, FileAccess.Read)))
      {
        FileInfo info = new FileInfo("dsa.cs.msg");
        message = reader.ReadBytes((int)info.Length);
      }

      //
      // Load the signature
      //   Signature is (r,s)
      //
      byte[] signature = null;
      using (BinaryReader reader = new BinaryReader(
          new FileStream("dsa.cs.sig", FileMode.Open, FileAccess.Read)))
      {
        FileInfo info = new FileInfo("dsa.cs.sig");
        signature = reader.ReadBytes((int)info.Length);
      }

      //
      // Compute h(m)
      //
      SHA1 sha = new SHA1CryptoServiceProvider();
      byte[] hash = sha.ComputeHash(message);

      //
      // Initialize Verifier
      //
      DSASignatureDeformatter verifier =
        new DSASignatureDeformatter(dsa);
      verifier.SetHashAlgorithm("SHA1");

      if (verifier.VerifySignature(hash, signature))
      {
        UTF8Encoding utf8 = new UTF8Encoding();
        String s = utf8.GetString(message);

        MessageBox.Show("Message Verified. Recovered String:\n" + s);
      }
      else
      {
        MessageBox.Show("Message Not Verified.");
      }

      // See http://blogs.msdn.com/tess/archive/2007/10/31/
      //   asp-net-crash-system-security-cryptography-cryptographicexception.aspx
      dsa.Clear();
    }

    private static void SignDsaMessage()
    {
      //
      // Load the Private Key
      //   PKCS#8 Format
      //
      AsnKeyParser keyParser =
        new AsnKeyParser("private.dsa.cs.key");

      DSAParameters privateKey = keyParser.ParseDSAPrivateKey();

      //
      // Initailize the CSP
      //   Supresses creation of a new key
      //
      CspParameters csp = new CspParameters();
      csp.KeyContainerName = "DSA Test (OK to Delete)";

      // Cannot use PROV_DSS_DH
      const int PROV_DSS = 3;
      csp.ProviderType = PROV_DSS;

      const int AT_SIGNATURE = 2;
      csp.KeyNumber = AT_SIGNATURE;

      //
      // Initialize the Provider
      //
      DSACryptoServiceProvider dsa =
        new DSACryptoServiceProvider(csp);
      dsa.PersistKeyInCsp = false;

      //
      // The moment of truth...
      //
      dsa.ImportParameters(privateKey);

      //
      // Sign the Message
      //
      DSASignatureFormatter signer =
        new DSASignatureFormatter(dsa);
      signer.SetHashAlgorithm("SHA1");

      // The one and only
      String m = "Crypto Interop: \u9aa8";
      byte[] message = Encoding.GetEncoding("UTF-8").GetBytes(m);

      // h(m)
      SHA1 sha = new SHA1CryptoServiceProvider();
      byte[] hash = sha.ComputeHash(message);

      // Create the Signature for h(m)
      byte[] signature = signer.CreateSignature(hash);

      // Write the message
      using (BinaryWriter writer = new BinaryWriter(
          new FileStream("dsa.cs.msg", FileMode.Create,
              FileAccess.ReadWrite)))
      {
        writer.Write(message);
      }

      // Write the signature on the message
      using (BinaryWriter writer = new BinaryWriter(
          new FileStream("dsa.cs.sig", FileMode.Create,
              FileAccess.ReadWrite)))
      {
        writer.Write(signature);
      }

      // See http://blogs.msdn.com/tess/archive/2007/10/31/
      //   asp-net-crash-system-security-cryptography-cryptographicexception.aspx
      dsa.Clear();
    }

    private static void CreateDsaKeys()
    {
      CspParameters csp = new CspParameters();

      csp.KeyContainerName = "DSA Test (OK to Delete)";

      const int PROV_DSS_DH = 13;
      csp.ProviderType = PROV_DSS_DH;

      const int AT_SIGNATURE = 2;
      csp.KeyNumber = AT_SIGNATURE;

      DSACryptoServiceProvider dsa =
          new DSACryptoServiceProvider(1024, csp);
      dsa.PersistKeyInCsp = false;

      // Encoded key
      AsnKeyBuilder.AsnMessage key = null;

      // Private Key
      DSAParameters privateKey = dsa.ExportParameters(true);
      key = AsnKeyBuilder.PrivateKeyToPKCS8(privateKey);

      using (BinaryWriter writer = new BinaryWriter(
          new FileStream("private.dsa.cs.key", FileMode.Create,
              FileAccess.ReadWrite)))
      {
        writer.Write(key.GetBytes());
      }

      // Public Key
      DSAParameters publicKey = dsa.ExportParameters(false);
      key = AsnKeyBuilder.PublicKeyToX509(publicKey);

      using (BinaryWriter writer = new BinaryWriter(
          new FileStream("public.dsa.cs.key", FileMode.Create,
              FileAccess.ReadWrite)))
      {
        writer.Write(key.GetBytes());
      }

      // See http://blogs.msdn.com/tess/archive/2007/10/31/
      //   asp-net-crash-system-security-cryptography-cryptographicexception.aspx
      dsa.Clear();
    }
  }
}
