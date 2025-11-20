using PowerShellTerminal.Infrastructure.Data;
using System.Windows.Forms;
namespace PowerShellTerminal.Infrastructure
{
    public static class DatabaseInitializer
    {
        public static void Initialize()
        {
            try
            {
                using var context = new TerminalDbContext();
                context.Database.EnsureCreated();
                Console.WriteLine("Database initialized successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database initialization failed: {ex.Message}");
            }
        }
    }
}