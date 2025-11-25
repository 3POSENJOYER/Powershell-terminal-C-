using Microsoft.EntityFrameworkCore;
using PowerShellTerminal.Domain.Entities;

namespace PowerShellTerminal.Infrastructure.Data
{
    public class TerminalDbContext : DbContext
    {
        // Constructor for dependency injection.
        public TerminalDbContext(DbContextOptions<TerminalDbContext> options)
            : base(options) { }

        // Constructor for standalone use (creates SQLite context automatically).
        public TerminalDbContext()
            : base(new DbContextOptionsBuilder<TerminalDbContext>()
                .UseSqlite("Data Source=terminal.db")
                .Options) { }

        public DbSet<CommandHistory> CommandHistories { get; set; }
        public DbSet<TerminalSession> TerminalSessions { get; set; }
        public DbSet<UserSettings> UserSettings { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Set table names explicitly.
            modelBuilder.Entity<CommandHistory>().ToTable("CommandHistory");
            modelBuilder.Entity<TerminalSession>().ToTable("TerminalSession");
            modelBuilder.Entity<UserSettings>().ToTable("UserSettings");
        }
    }
}
