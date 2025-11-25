using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Repositories;

namespace PowerShellTerminal.Application.Services
{
    public class HistoryService
    {
        private CommandHistoryRepository _commandHistoryRepo;
        private UserSettingsRepository _userSettingsRepo;
        private TerminalSessionRepository _sessionRepo;

        public HistoryService()
        {
            
            InitializeDatabase();
            
            _commandHistoryRepo = new CommandHistoryRepository();
            _userSettingsRepo = new UserSettingsRepository();
            _sessionRepo = new TerminalSessionRepository();
        }

        private void InitializeDatabase()
        {
            try
            {
                using var context = new Infrastructure.Data.TerminalDbContext();
                bool created = context.Database.EnsureCreated();
                Console.WriteLine($"Database initialized: {created}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database initialization failed: {ex.Message}");
            }
        }

        public async Task SaveCommandAsync(string command, string output, string errors, bool success, string workingDirectory, int sessionId)
        {
            try
            {
                Console.WriteLine($"Saving command to database: {command}");
                
                await _commandHistoryRepo.AddAsync(new CommandHistory
                {
                    Command = command,
                    Output = output,
                    Errors = errors,
                    Success = success,
                    ExecutedAt = DateTime.Now,
                    WorkingDirectory = workingDirectory,
                    SessionId = sessionId
                });
                
                Console.WriteLine($" Command successfully saved to database: {command}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Failed to save command to database: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        public async Task<List<CommandHistory>> GetRecentCommandsAsync(int count = 50)
        {
            try
            {
                return await _commandHistoryRepo.GetRecentCommandsAsync(count);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to get recent commands: {ex.Message}");
                return new List<CommandHistory>();
            }
        }

        public async Task<UserSettings> LoadUserSettingsAsync()
        {
            try
            {
                return await _userSettingsRepo.GetUserSettingsAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load user settings: {ex.Message}");
                return new UserSettings();
            }
        }

        public async Task TestDatabaseConnection()
        {
            try
            {
                Console.WriteLine(" Testing database connection...");
                
               
                using var context = new Infrastructure.Data.TerminalDbContext();
                bool created = context.Database.EnsureCreated();
                Console.WriteLine($"Database ensured: {created}");
                
                
                var testSettings = await _userSettingsRepo.GetUserSettingsAsync();
                Console.WriteLine($" Database connection: OK");
                Console.WriteLine($" Current user: {testSettings.UserName}");
                
                
                var recentCommands = await _commandHistoryRepo.GetRecentCommandsAsync(1);
                Console.WriteLine($"Commands in database: {recentCommands.Count}");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Database connection failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        public async Task SaveUserSettingsAsync(UserSettings settings)
        {
            try
            {
                await _userSettingsRepo.SaveUserSettingsAsync(settings);
                Console.WriteLine("✅ User settings saved to database");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to save user settings: {ex.Message}");
            }
        }
    }
}