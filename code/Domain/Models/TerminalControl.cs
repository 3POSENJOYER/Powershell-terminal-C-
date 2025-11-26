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
            // Основні налаштування
            this.Dock = DockStyle.Fill;
            this.BackColor = Color.Black;

            // Вихідне поле
            _outputBox = new RichTextBox();
            _outputBox.Dock = DockStyle.Fill;
            _outputBox.BackColor = Color.Black;
            _outputBox.ForeColor = Color.Lime;
            _outputBox.Font = new Font("Consolas", 10);
            _outputBox.ReadOnly = true;
            _outputBox.BorderStyle = BorderStyle.None;
            _outputBox.ScrollBars = RichTextBoxScrollBars.Vertical;

            // Панель вводу
            _inputPanel = new Panel();
            _inputPanel.Dock = DockStyle.Bottom;
            _inputPanel.Height = 30;
            _inputPanel.BackColor = Color.Black;

            // Промпт
            _promptLabel = new Label();
            _promptLabel.Text = "PS> ";
            _promptLabel.ForeColor = Color.White;
            _promptLabel.BackColor = Color.Black;
            _promptLabel.Font = new Font("Consolas", 10);
            _promptLabel.Dock = DockStyle.Left;
            _promptLabel.Width = 40;
            _promptLabel.TextAlign = ContentAlignment.MiddleLeft;

            // Поле вводу
            _inputBox = new TextBox();
            _inputBox.Dock = DockStyle.Fill;
            _inputBox.BackColor = Color.Black;
            _inputBox.ForeColor = Color.White;
            _inputBox.Font = new Font("Consolas", 10);
            _inputBox.BorderStyle = BorderStyle.FixedSingle;

            // Додаємо обробник подій для поля вводу
            _inputBox.KeyDown += InputBox_KeyDown;

            // Додаємо елементи на панель вводу
            _inputPanel.Controls.Add(_inputBox);
            _inputPanel.Controls.Add(_promptLabel);

            // Додаємо елементи на форму
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
            // Показуємо команду
            WriteOutput($"PS> {command}", Color.Yellow);

            try
            {
                // Виконуємо команду
                string result = await _interpreter.ExecuteCommand(command);
                
                // Показуємо результат
                if (!string.IsNullOrWhiteSpace(result))
                {
                    WriteOutput(result, Color.Lime);
                }

                // Зберігаємо в історію
                await SaveCommandToHistory(command, result);
            }
            catch (Exception ex)
            {
                WriteOutput($"Error: {ex.Message}", Color.Red);
            }

            WriteOutput("", Color.Lime); // Пустий рядок
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
                    Directory.GetCurrentDirectory(),
                    _sessionId
                );

                Console.WriteLine($"✅ Command saved to database: {command}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to save command: {ex.Message}");
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
            _outputBox.Font = font;
            _inputBox.Font = font;
            _promptLabel.Font = font;
        }

        public Control AsControl() => this;
    }
}