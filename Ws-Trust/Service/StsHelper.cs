using System.Security.Cryptography.X509Certificates;

namespace Ws_Trust.Service
{
    public class StsHelper
    {
        public StsHelper()
        {
        }

        public static X509Certificate2 GetCertificate()
        {
            return GetCertificate("localhost");
        }
        public static X509Certificate2 GetCertificate(string name)
        {
            X509Certificate2 cer =null;
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindBySubjectName, name, false);
            if (cers.Count > 0)
            {
                cer = cers[0];
            };
            store.Close();
            return cer;
        }
    }
}