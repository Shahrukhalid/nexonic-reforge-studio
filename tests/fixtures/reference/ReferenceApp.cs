// Nexonic ReForge Studio — Ground Truth .NET/C# Reference Application
// Purpose: Legally authorized ground-truth reference fixture with documented namespaces,
//          classes, methods, and interface contracts.

using System;

namespace Nexonic.ReForge.Reference
{
    public interface ICalculator
    {
        int Add(int a, int b);
        int Factorial(int n);
    }

    public class ReferenceCalculator : ICalculator
    {
        public const string ServiceEndpoint = "https://ref.internal/v1/calc";

        public int Add(int a, int b) => a + b;

        public int Factorial(int n)
        {
            if (n <= 1) return 1;
            int acc = 1;
            for (int i = 2; i <= n; i++) acc *= i;
            return acc;
        }

        public static void Main(string[] args)
        {
            var calc = new ReferenceCalculator();
            Console.WriteLine($"Result: {calc.Add(20, 22)}");
        }
    }
}
