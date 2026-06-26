// Arquivo de teste com vulnerabilidades C#
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnApp
{
    public class VulnCsharp
    {
        // SQL Injection
        public void GetUser(string userId)
        {
            string connectionString = "Server=localhost;Database=mydb;User Id=sa;Password=Admin123!;";
            using var conn = new SqlConnection(connectionString);
            conn.Open();
            string query = "SELECT * FROM Users WHERE Id = " + userId;
            using var cmd = new SqlCommand(query, conn);
            var reader = cmd.ExecuteReader();
        }

        // Command Injection
        public string RunCommand(string userInput)
        {
            var process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + userInput;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            return process.StandardOutput.ReadToEnd();
        }

        // Weak Cryptography
        public string HashPassword(string password)
        {
            using var md5 = MD5.Create();
            byte[] inputBytes = Encoding.ASCII.GetBytes(password);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            return Convert.ToHexString(hashBytes);
        }

        // Hardcoded credentials
        private const string ApiKey = "sk-1234567890abcdef";
        private const string DbPassword = "production_password_123";

        // Path Traversal
        public string ReadFile(string filename)
        {
            string path = Path.Combine("/data", filename);
            return File.ReadAllText(path);
        }

        // Insecure Deserialization
        public object Deserialize(byte[] data)
        {
            var formatter = new BinaryFormatter();
            using var stream = new MemoryStream(data);
            return formatter.Deserialize(stream);
        }

        // XSS (in web context)
        public string RenderSearch(string query)
        {
            return "<html><body><h1>Results for: " + query + "</h1></body></html>";
        }
    }
}
