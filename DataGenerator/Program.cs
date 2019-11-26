using System;
using Cassandra;
using Cassandra.Mapping;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace DataGenerator
{
    public class Program
    {
        // Cassandra Cluster Configs      
        private const string UserName = "UserName";
        private const string Password = "Password";
        private const string CassandraContactPoint = "CassandraContactPoint";  // DnsName  
        private static int CassandraPort = 10350;
        public static void Main(string[] args)
        {
            // Connect to cassandra cluster  (Cassandra API on Azure Cosmos DB supports only TLSv1.2)
            var options = new Cassandra.SSLOptions(SslProtocols.Tls12, true, ValidateServerCertificate);
            options.SetHostNameResolver((ipAddress) => CassandraContactPoint);
            Cluster cluster = Cluster.Builder().WithCredentials(UserName, Password).WithPort(CassandraPort).AddContactPoint(CassandraContactPoint).WithSSL(options).Build();
            ISession session = cluster.Connect();

            session = cluster.Connect("uprofile");
            IMapper mapper = new Mapper(session);

            // Inserting Data into user table
            int i = 0;
            while (true)
            {
                Console.WriteLine("inserting record:" + i);
                mapper.Insert<User>(new User(i, "record"+i, "record"+i));
                i++;
            }
            
        }

        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
    }
}
