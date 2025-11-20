using Microsoft.EntityFrameworkCore;
using PowerShellTerminal.Domain.Entities;

namespace PowerShellTerminal.Infrastructure.Data
{
    public class TerminalDbContext : DbContext
    {
        public DbSet<CommandHistory> CommandHistories { get; set; }
        public DbSet<UserSettings> UserSettings { get; set; }
        public DbSet<TerminalSession> TerminalSessions { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            // Створюємо базу даних в папці програми
            var databasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "powershellterminal.db");
            var connectionString = $"Data Source={databasePath}";
            
            optionsBuilder.UseSqlite(connectionString);
            optionsBuilder.EnableSensitiveDataLogging(); // Додаємо для детального логування
            
            Console.WriteLine($"📁 Database path: {databasePath}");
            Console.WriteLine($"🔗 Connection string: {connectionString}");
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Конфігурація для CommandHistory
            modelBuilder.Entity<CommandHistory>(entity =>
            {
                entity.ToTable("CommandHistories");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).ValueGeneratedOnAdd();
                entity.Property(e => e.Command).IsRequired().HasMaxLength(1000);
                entity.Property(e => e.Output).HasColumnType("TEXT");
                entity.Property(e => e.Errors).HasColumnType("TEXT");
                entity.Property(e => e.ExecutedAt).IsRequired();
                entity.Property(e => e.WorkingDirectory).HasMaxLength(500);
                entity.Property(e => e.SessionId);
            });

            // Конфігурація для UserSettings
            modelBuilder.Entity<UserSettings>(entity =>
            {
                entity.ToTable("UserSettings");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).ValueGeneratedOnAdd();
                entity.Property(e => e.UserName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.ThemeName).HasMaxLength(50);
                entity.Property(e => e.FontFamily).HasMaxLength(50);
                entity.Property(e => e.FontSize);
                entity.Property(e => e.BackgroundColor).HasMaxLength(20);
                entity.Property(e => e.ForegroundColor).HasMaxLength(20);
                entity.Property(e => e.WindowWidth);
                entity.Property(e => e.WindowHeight);
                entity.Property(e => e.LastModified).IsRequired();
            });

            // Конфігурація для TerminalSession
            modelBuilder.Entity<TerminalSession>(entity =>
            {
                entity.ToTable("TerminalSessions");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).ValueGeneratedOnAdd();
                entity.Property(e => e.SessionName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.StartedAt).IsRequired();
                entity.Property(e => e.EndedAt);
                entity.Property(e => e.InitialDirectory).HasMaxLength(500);
                entity.Property(e => e.IsActive).IsRequired();
            });

            base.OnModelCreating(modelBuilder);
        }
    }
}