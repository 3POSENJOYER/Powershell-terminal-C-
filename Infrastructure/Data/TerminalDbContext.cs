public class TerminalDbContext
{
    public DbSet<CommandHistory> CommandHistories { get; set; }
    public DbSet<UserSettings> UserSettings { get; set; }
    public DbSet<TerminalSession> TerminalSessions { get; set; }

    public Task SaveChangesAsync() => null;
}