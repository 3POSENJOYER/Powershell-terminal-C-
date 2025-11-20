using System;
using System.Diagnostics;
using System.Linq;
using System.Windows.Forms;
using PowerShellTerminal.Infrastructure.Repositories;
using PowerShellTerminal.Domain.Entities;

namespace PowerShellTerminal
{
    public partial class MainForm : Form
    {
        private CommandHistoryRepository _repository;

        public MainForm()
        {
            InitializeComponent();
            _repository = new CommandHistoryRepository();
            SetupTerminal();
        }

        private void SetupTerminal()
        {
            terminalBox.ReadOnly = false;
            terminalBox.ShortcutsEnabled = false;

            terminalBox.KeyDown += TerminalBox_KeyDown;

            terminalBox.Text = "PS> ";
            terminalBox.SelectionStart = terminalBox.Text.Length;
        }

        private void TerminalBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;

                string fullText = terminalBox.Text;
                string commandLine = fullText.Split('\n').Last();

                string command = commandLine.Replace("PS> ", "").Trim();

                ExecuteCommand(command);
            }
        }

        private async void ExecuteCommand(string command)
        {
            if (string.IsNullOrWhiteSpace(command))
            {
                terminalBox.AppendText("\nPS> ");
                return;
            }

            try
            {
                var psi = new ProcessStartInfo()
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = Process.Start(psi);

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                string result = output + error;

                terminalBox.AppendText("\n" + result + "\nPS> ");

                await _repository.AddAsync(new CommandHistory
                {
                    Command = command,
                    Output = result,
                    ExecutedAt = DateTime.Now
                });
            }
            catch (Exception ex)
            {
                terminalBox.AppendText("\nERROR: " + ex.Message + "\nPS> ");
            }
        }
    }
}
