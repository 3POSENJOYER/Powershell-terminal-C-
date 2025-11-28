using System.Threading.Tasks;
using PowerShellTerminal.Application.Patterns.Command;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public class SaveHistoryCommand : ICommand
    {
        private readonly HistoryService _historyService;
        private readonly string _command;
        private readonly string _output;
        private readonly string _errors;
        private readonly bool _success;
        private readonly string _workingDirectory;
        private readonly int _sessionId;

        public SaveHistoryCommand(HistoryService historyService, string command, string output, string errors, bool success, string workingDirectory, int sessionId)
        {
            _historyService = historyService;
            _command = command;
            _output = output;
            _errors = errors;
            _success = success;
            _workingDirectory = workingDirectory;
            _sessionId = sessionId;
        }

        public async Task ExecuteAsync()
        {
            await _historyService.SaveCommandAsync(_command, _output, _errors, _success, _workingDirectory, _sessionId);
        }
    }
}
