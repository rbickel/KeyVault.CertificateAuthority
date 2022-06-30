namespace KeyVault.CertificateTests;

using Microsoft.Extensions.Configuration;

public class Config
{

    private static Config _instance;
    private IConfiguration _configuration;
    private static object _lock = new object();

    private Config()
    {
        _configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", false, true)
            .Build();
    }

    public static Config Instance
    {
        get
        {
            lock (_lock)
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance = new Config();
                    }
                }
            }
            return _instance;
        }
    }

    public string KeyVaultUri {
        get{
            return _configuration.GetValue<string>(nameof(KeyVaultUri));
        }
    }
}