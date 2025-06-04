using System;
using System.Security;
using System.Security.Cryptography; // Added for CryptographicException
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using OneIdentity.SafeguardDotNet;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            // Configure application settings
            IConfiguration config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            // Retrieve Safeguard configuration values
            string? applianceAddress = config["Safeguard:ApplianceAddress"];
            string? certificateThumbprint = config["Safeguard:CertificateThumbprint"];
            string? apiKey = config["Safeguard:ApiKey"];
            string? apiVersionStr = config["Safeguard:ApiVersion"];
            string? certificateSource = config["Safeguard:CertificateSource"];
            string? pfxPath = config["Safeguard:PfxPath"];
            string? pfxPassword = config["Safeguard:PfxPassword"];

            // Validate essential configuration
            if (string.IsNullOrEmpty(applianceAddress) ||
                string.IsNullOrEmpty(certificateThumbprint) ||
                string.IsNullOrEmpty(apiKey) ||
                string.IsNullOrEmpty(apiVersionStr) ||
                string.IsNullOrEmpty(certificateSource))
            {
                throw new Exception("One or more required configuration values in appsettings.json are missing or invalid. " +
                                    "Please ensure 'Safeguard:ApplianceAddress', 'Safeguard:CertificateThumbprint', " +
                                    "'Safeguard:ApiKey', 'Safeguard:ApiVersion', and 'Safeguard:CertificateSource' are correctly set.");
            }

            // Parse API version
            if (!int.TryParse(apiVersionStr, out int apiVersion))
            {
                throw new Exception("Invalid API version format in appsettings.json. 'Safeguard:ApiVersion' must be an integer.");
            }

            // Validate PFX path if certificate source is PFX
            if (certificateSource!.ToLowerInvariant() == "pfx" && string.IsNullOrEmpty(pfxPath))
            {
                throw new Exception("PfxPath is required in appsettings.json when CertificateSource is set to 'pfx'.");
            }

            // Get client certificate from store or PFX file
            X509Certificate2 clientCertificate = GetCertificateFromStore(
                certificateThumbprint!,
                certificateSource!,
                pfxPath,
                pfxPassword);

            // Establish A2A context and retrieve password
            using (var a2aContext = Safeguard.A2A.GetContext(applianceAddress!, certificateThumbprint!, apiVersion, true))
            {
                // Convert API key to SecureString for security
                SecureString secureApiKey = new SecureString();
                foreach (char c in apiKey!)
                {
                    secureApiKey.AppendChar(c);
                }
                secureApiKey.MakeReadOnly();

                var password = a2aContext.RetrievePassword(secureApiKey);
                Console.WriteLine($"Retrieved database password: {password}");
            }
        }
        catch (Exception ex)
        {
            // Handle and display any unexpected errors
            Console.Error.WriteLine($"An unexpected error occurred: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.Error.WriteLine($"Inner Error details: {ex.InnerException.Message}");
            }
        }
    }

    /// <summary>
    /// Retrieves an X.509 certificate either from the Windows certificate store or a PFX file.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate to find in the keystore.</param>
    /// <param name="certificateSource">Specifies where to get the certificate: "keystore" or "pfx".</param>
    /// <param name="pfxPath">The path to the PFX file (required if certificateSource is "pfx").</param>
    /// <param name="pfxPassword">The password for the PFX file (optional for unencrypted PFX).</param>
    /// <returns>An X509Certificate2 object.</returns>
    /// <exception cref="ArgumentNullException">Thrown if thumbprint or certificateSource is null or empty, or if pfxPath is null/empty when certificateSource is "pfx".</exception>
    /// <exception cref="Exception">Thrown if the certificate is not found, PFX file operations fail, or an invalid certificateSource is provided.</exception>
    private static X509Certificate2 GetCertificateFromStore(
        string thumbprint,
        string certificateSource,
        string? pfxPath,
        string? pfxPassword)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentNullException(nameof(thumbprint), "Certificate thumbprint cannot be null or empty.");
        }

        if (string.IsNullOrEmpty(certificateSource))
        {
            throw new ArgumentNullException(nameof(certificateSource), "CertificateSource cannot be null or empty.");
        }

        certificateSource = certificateSource.ToLowerInvariant();

        if (certificateSource == "keystore")
        {
            // Clean and normalize the thumbprint
            string cleanedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, cleanedThumbprint, false);

                if (certCollection.Count == 0)
                {
                    throw new Exception($"Certificate with thumbprint '{cleanedThumbprint}' was not found in the Local Machine store (Personal). " +
                                        "Please ensure it is installed correctly.");
                }
                return certCollection[0];
            }
        }
        else if (certificateSource == "pfx")
        {
            if (string.IsNullOrEmpty(pfxPath))
            {
                throw new ArgumentNullException(nameof(pfxPath), "PfxPath is required when CertificateSource is set to 'pfx'.");
            }
            try
            {
                // Use the recommended method to load PFX files in .NET 8+
                return new X509Certificate2(pfxPath, pfxPassword); // Directly create for PFX
            }
            catch (System.IO.FileNotFoundException ex)
            {
                throw new Exception($"PFX certificate file not found at '{pfxPath}'. Please verify the path. Error: {ex.Message}", ex);
            }
            catch (CryptographicException ex)
            {
                throw new Exception($"Failed to load PFX certificate from '{pfxPath}'. " +
                                    "Ensure the password is correct and the PFX file is valid. Error: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"An unexpected error occurred while loading PFX certificate from '{pfxPath}'. Error: {ex.Message}", ex);
            }
        }
        else
        {
            throw new ArgumentException($"Invalid CertificateSource value '{certificateSource}'. Supported values are 'keystore' or 'pfx'.");
        }
    }
}