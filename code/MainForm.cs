using System;
using System.Diagnostics;
using System.Linq;
using System.Windows.Forms;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Repositories;
using PowerShellTerminal.Application.Patterns.Command;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal
{
    public partial class MainForm : Form
    {
        private readonly CommandHistoryRepository _repository;
        private readonly CommandInvoker _invoker;
        private readonly HistoryService _historyService;
        private const string PROMPT = "PS> ";

        public MainForm()
        {
            InitializeComponent();
            _repository = new CommandHistoryRepository();
            _invoker = new CommandInvoker();
            _historyService = new HistoryService();
            SetupTerminal();
        }

        private void SetupTerminal()
        {
            terminalBox.ReadOnly = false;
            terminalBox.ShortcutsEnabled = false;
            terminalBox.KeyDown += TerminalBox_KeyDown;
            terminalBox.Text = PROMPT;
            terminalBox.SelectionStart = terminalBox.Text.Length;
        }

        private void TerminalBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;

            string fullText = terminalBox.Text;
            string lastLine = fullText.Split('\n').Last();
            string command = lastLine.Replace(PROMPT, string.Empty).Trim();

            if (!string.IsNullOrEmpty(command))
            {
                _ = ExecuteCommand(command);
            }

            terminalBox.AppendText($"\n{PROMPT}");
        }

        private async System.Threading.Tasks.Task ExecuteCommand(string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return;

                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();
                string result = output + error;

                terminalBox.AppendText(result);

                var saveCmd = new SaveHistoryCommand(_historyService, command, result, string.Empty, true, Environment.CurrentDirectory, 0);
                await _invoker.InvokeAsync(saveCmd);
            }
            catch (Exception ex)
            {
                terminalBox.AppendText($"Error: {ex.Message}\n");
            }
        }
    }
}
