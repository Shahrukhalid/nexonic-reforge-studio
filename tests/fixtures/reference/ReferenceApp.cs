// Nexonic ReForge Studio — Ground Truth .NET/C# Reference Application
// Purpose: Legally authorized ground-truth reference fixture with documented namespaces,
//          classes, methods, and interface contracts.

using System;

namespace Nexonic.ReForge.Reference
{
    public interface ICalculator
    {
        int AddNumbers(int a, int b);
        int Factorial(int n);
        bool ValidateLicenseKey(string key);
        string GetHealthStatus();
    }

    public class ReferenceApp : ICalculator
    {
        public const string ServiceEndpoint = "https://ref.internal/v1/calc";

        public int AddNumbers(int a, int b)
        {
            return a + b;
        }

        public int Factorial(int n)
        {
            if (n <= 1) return 1;
            int acc = 1;
            for (int i = 2; i <= n; i++) acc *= i;
            return acc;
        }

        public bool ValidateLicenseKey(string key)
        {
            return key == "reforge_net_license_valid_2026";
        }

        public string GetHealthStatus()
        {
            return "HEALTHY_ACTIVE";
        }

        public static void Main(string[] args)
        {
            var app = new ReferenceApp();
            Console.WriteLine("[REF_NET] Reference .NET App Initialized");
            Console.WriteLine(string.Format("Result: {0}", app.AddNumbers(20, 22)));
        }
    }
}
