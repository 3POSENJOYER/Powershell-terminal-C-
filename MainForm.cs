using System;
using System.Drawing;
using System.Windows.Forms;

namespace PowerShellTerminal
{
    public class MainForm : Form
    {
        private readonly PowerShellInterpreter _interpreter;
        private readonly TextBox _outputTextBox;
        private readonly TextBox _inputTextBox;
        
        public MainForm()
        {
            // Спочатку ініціалізуємо TextBox
            _outputTextBox = new TextBox();
            _inputTextBox = new TextBox();
            _interpreter = new PowerShellInterpreter();
            
            InitializeComponent();
        }
        
        private void InitializeComponent()
        {
            // Налаштування форми
            Text = "PowerShell Terminal";
            Size = new Size(800, 600);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.Black;
            
            // Налаштування TextBox для виводу
            _outputTextBox.Multiline = true;
            _outputTextBox.ScrollBars = ScrollBars.Vertical;
            _outputTextBox.Dock = DockStyle.Fill;
            _outputTextBox.ReadOnly = true;
            _outputTextBox.BackColor = Color.Black;
            _outputTextBox.ForeColor = Color.Lime;
            _outputTextBox.Font = new Font("Consolas", 11);
            _outputTextBox.BorderStyle = BorderStyle.None;
            
            // Налаштування TextBox для вводу
            _inputTextBox.Dock = DockStyle.Bottom;
            _inputTextBox.BackColor = Color.Black;
            _inputTextBox.ForeColor = Color.White;
            _inputTextBox.Font = new Font("Consolas", 11);
            _inputTextBox.BorderStyle = BorderStyle.FixedSingle;
            _inputTextBox.Height = 30;
            
            // Додаємо підказку
            _inputTextBox.PlaceholderText = "Введіть PowerShell команду та натисніть Enter...";
            
            // Обробник події для вводу команд
            _inputTextBox.KeyDown += async (sender, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    var command = _inputTextBox.Text.Trim();
                    if (!string.IsNullOrEmpty(command))
                    {
                        _inputTextBox.Clear();
                        
                        // Додаємо команду до виводу
                        _outputTextBox.AppendText($"PS> {command}\r\n");
                        
                        // Виконуємо команду
                        var result = await _interpreter.InterpretAsync(command);
                        
                        // Додаємо результат до виводу
                        if (result.Success && !string.IsNullOrEmpty(result.Output))
                        {
                            _outputTextBox.AppendText($"{result.Output}\r\n");
                        }
                        else if (!string.IsNullOrEmpty(result.Errors))
                        {
                            _outputTextBox.AppendText($"ПОМИЛКА: {result.Errors}\r\n");
                        }
                        
                        _outputTextBox.AppendText("\r\n");
                        _outputTextBox.SelectionStart = _outputTextBox.Text.Length;
                        _outputTextBox.ScrollToCaret();
                    }
                    e.Handled = true;
                    e.SuppressKeyPress = true;
                }
            };
            
            // Додаємо обробник для активації форми
            this.Shown += (sender, e) =>
            {
                _inputTextBox.Focus();
            };
            
            // Додаємо обробник кліку на вихідному TextBox
            _outputTextBox.Click += (sender, e) =>
            {
                _inputTextBox.Focus();
            };
            
            // Додаємо елементи на форму
            Controls.Add(_outputTextBox);
            Controls.Add(_inputTextBox);
        }
        
        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            _inputTextBox.Focus();
        }
    }
}