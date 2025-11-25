using System;
using PowerShellTerminal.Infrastructure.Data;

namespace PowerShellTerminal.Infrastructure
{
    public static class DatabaseInitializer
    {
        // Initialize the database and ensure it's created.
        public static void Initialize()
        {
            try
            {
                using var context = new TerminalDbContext();
                context.Database.EnsureCreated();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DB init error: {ex.Message}");
            }
        }
    }
}