using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Repositories;

namespace PowerShellTerminal.Application.Services
{
    public class HistoryService
    {
        private readonly CommandHistoryRepository _commandHistoryRepo;
        private readonly UserSettingsRepository _userSettingsRepo;
        private readonly TerminalSessionRepository _sessionRepo;

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
                context.Database.EnsureCreated();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database init error: {ex.Message}");
            }
        }

        public async Task SaveCommandAsync(string command, string output, string errors, bool success, string workingDirectory, int sessionId)
        {
            try
            {
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
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Save error: {ex.Message}");
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
                Console.WriteLine($"Fetch error: {ex.Message}");
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
                Console.WriteLine($"Load settings error: {ex.Message}");
                return new UserSettings();
            }
        }

        public async Task SaveUserSettingsAsync(UserSettings settings)
        {
            try
            {
                await _userSettingsRepo.SaveUserSettingsAsync(settings);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Save settings error: {ex.Message}");
            }
        }
    }
}