using PowerShellTerminal.Application.Services;
using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalControl : UserControl
    {
        private RichTextBox _outputBox;
        private TextBox _inputBox;
        private Label _promptLabel;
        private Panel _inputPanel;
        private Button _closeButton;
        private CommandInterpreter _interpreter;
        private HistoryService _historyService;
        private int _sessionId;

        public TerminalControl(CommandInterpreter interpreter, HistoryService historyService, int sessionId)
        {
            _interpreter = interpreter;
            _historyService = historyService;
            _sessionId = sessionId;
            InitializeComponent();
            ShowWelcomeMessage();
        }

        private void InitializeComponent()
        {
            this.Dock = DockStyle.Fill;
            this.BackColor = Color.Black;

            _outputBox = new RichTextBox();
            _outputBox.Dock = DockStyle.Fill;
            _outputBox.BackColor = Color.Black;
            _outputBox.ForeColor = Color.Lime;
            _outputBox.Font = new Font("Consolas", 10);
            _outputBox.ReadOnly = true;
            _outputBox.BorderStyle = BorderStyle.None;
            _outputBox.ScrollBars = RichTextBoxScrollBars.Vertical;

            _inputPanel = new Panel();
            _inputPanel.Dock = DockStyle.Bottom;
            _inputPanel.Height = 30;
            _inputPanel.BackColor = Color.Black;


            _promptLabel = new Label();
            _promptLabel.Text = "PS> ";
            _promptLabel.ForeColor = Color.White;
            _promptLabel.BackColor = Color.Black;
            _promptLabel.Font = new Font("Consolas", 10);
            _promptLabel.Dock = DockStyle.Left;
            _promptLabel.Width = 40;
            _promptLabel.TextAlign = ContentAlignment.MiddleLeft;

            _inputBox = new TextBox();
            _inputBox.Dock = DockStyle.Fill;
            _inputBox.BackColor = Color.Black;
            _inputBox.ForeColor = Color.White;
            _inputBox.Font = new Font("Consolas", 10);
            _inputBox.BorderStyle = BorderStyle.FixedSingle;
            _inputBox.KeyDown += InputBox_KeyDown;

            _closeButton = new Button();
            _closeButton.Text = "X";
            _closeButton.Dock = DockStyle.Right;
            _closeButton.Width = 30;
            _closeButton.BackColor = Color.FromArgb(70, 70, 70);
            _closeButton.ForeColor = Color.White;
            _closeButton.FlatStyle = FlatStyle.Flat;
            _closeButton.FlatAppearance.BorderSize = 0;
            _closeButton.Click += CloseButton_Click;

            _inputPanel.Controls.Add(_closeButton);
            _inputPanel.Controls.Add(_inputBox);
            _inputPanel.Controls.Add(_promptLabel);

            this.Controls.Add(_outputBox);
            this.Controls.Add(_inputPanel);
        }

        private void CloseButton_Click(object sender, EventArgs e)
        {
            if (this.Parent is TabPage tabPage)
            {
                if (tabPage.Parent is TabControl tabControl)
                {
                    tabControl.TabPages.Remove(tabPage);
                }
            }
            else if (this.Parent != null)
            {
                this.Parent.Controls.Remove(this);
            }
            this.Dispose();
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
                string result = await _interpreter.ExecuteCommand(command);
                
                if (!string.IsNullOrWhiteSpace(result))
                {
                    WriteOutput(result, Color.Lime);
                }

                await SaveCommandToHistory(command, result);
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
                                                                            
                await _historyService.SaveCommandAsync(
                    command,
                    output ?? "",
                    "",
                    success,
                    System.IO.Directory.GetCurrentDirectory(),
                    _sessionId
                );

                Console.WriteLine($"Command saved to database: {command}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save command: {ex.Message}");
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
            WriteOutput("", Color.Lime);
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
            if (font == null)
            {
                return;
            }

            _outputBox.Font = font;
            _inputBox.Font = font;
            _promptLabel.Font = font;
        }

        public Control AsControl() => this;
    }
}