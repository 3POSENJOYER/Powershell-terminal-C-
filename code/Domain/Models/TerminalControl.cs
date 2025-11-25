using System;
using System.IO;
using System.Threading.Tasks;
using PowerShellTerminal.Application.Services;
using System.Drawing;
using System.Windows.Forms;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalControl : UserControl
    {
        private RichTextBox _outputBox;
        private TextBox _inputBox;
        private Label _promptLabel;
        private Panel _inputPanel;
        private CommandInterpreter _interpreter;
        private HistoryService _historyService;

        public TerminalControl(CommandInterpreter interpreter, HistoryService historyService)
        {
            _interpreter = interpreter;
            _historyService = historyService;
            InitializeComponent();
            ShowWelcomeMessage();
        }

        private void InitializeComponent()
        {
            this.Dock = DockStyle.Fill;
            this.BackColor = Color.Black;

            _outputBox = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ForeColor = Color.Lime,
                Font = new Font("Consolas", 10),
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };

            _inputPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 30,
                BackColor = Color.Black
            };

            _promptLabel = new Label
            {
                Text = "PS> ",
                ForeColor = Color.White,
                BackColor = Color.Black,
                Font = new Font("Consolas", 10),
                Dock = DockStyle.Left,
                Width = 40,
                TextAlign = ContentAlignment.MiddleLeft
            };

            _inputBox = new TextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Black,
                ForeColor = Color.White,
                Font = new Font("Consolas", 10),
                BorderStyle = BorderStyle.FixedSingle
            };

            _inputBox.KeyDown += InputBox_KeyDown;

            _inputPanel.Controls.Add(_inputBox);
            _inputPanel.Controls.Add(_promptLabel);
  
            this.Controls.Add(_outputBox);
            this.Controls.Add(_inputPanel);
        }

        private void InputBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                
                string command = _inputBox.Text.Trim();
                if (!string.IsNullOrEmpty(command))
                {
                    _ = ExecuteCommandAsync(command);
                }
                _inputBox.Clear();
            }
        }

        private async Task ExecuteCommandAsync(string command)
        {
            WriteOutput($"PS> {command}", Color.Yellow);

            try
            {
                var result = await _interpreter.ExecuteCommand(command);

                if (!string.IsNullOrWhiteSpace(result?.Output))
                {
                    WriteOutput(result.Output, Color.Lime);
                }

                await SaveCommandToHistory(command, result?.Output);
            }
            catch (Exception ex)
            {
                WriteOutput($"Error: {ex.Message}", Color.Red);
            }

            WriteOutput("", Color.Lime);
        }

        private async Task SaveCommandToHistory(string command, string output)
        {
            try
            {
                bool success = !string.IsNullOrEmpty(output) && 
                              !output.Contains("Error:") && 
                              !output.Contains("Exception:");

                await _historyService.SaveCommandAsync(command, output ?? "", string.Empty, success, Directory.GetCurrentDirectory(), 1);

                Console.WriteLine($"Command saved to database: {command}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Failed to save command: {ex.Message}");
                WriteOutput($"History error: {ex.Message}", Color.Red);
            }
        }

        private void WriteOutput(string text, Color color)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => WriteOutput(text, color)));
                return;
            }

            _outputBox.SelectionStart = _outputBox.TextLength;
            _outputBox.SelectionColor = color;
            _outputBox.AppendText(text + Environment.NewLine);
            _outputBox.SelectionColor = _outputBox.ForeColor;
            _outputBox.ScrollToCaret();
        }

        private void ShowWelcomeMessage()
        {
            WriteOutput("PowerShell Terminal - Ready", Color.Cyan);
            WriteOutput("Type your PowerShell commands below:", Color.Gray);
            WriteOutput(string.Empty, Color.Lime);
        }

        public void FocusInput()
        {
            _inputBox.Focus();
        }

        public void SetBackgroundColor(Color color)
        {
            _outputBox.BackColor = color;
            _inputBox.BackColor = color;
            _inputPanel.BackColor = color;
            this.BackColor = color;
        }

        public void SetForegroundColor(Color color)
        {
            _outputBox.ForeColor = color;
            _inputBox.ForeColor = color;
            _promptLabel.ForeColor = color;
        }

        public void SetFont(Font font)
        {
            _outputBox.Font = font;
            _inputBox.Font = font;
            _promptLabel.Font = font;
        }

        public Control AsControl() => this;
    }
}