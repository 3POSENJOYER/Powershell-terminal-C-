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

		private static int TerminalCount = 1;
			
			public void AppendOutput(string text)
			{
				_outputTextBox.AppendText(text);
			}

        public MainForm()
        {
            _outputTextBox = new TextBox();
            _inputTextBox = new TextBox();
            _interpreter = new PowerShellInterpreter();

            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"PowerShell Terminal #{TerminalCount}";
            Size = new Size(800, 600);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.Black;

            _outputTextBox.Multiline = true;
            _outputTextBox.ScrollBars = ScrollBars.Vertical;
            _outputTextBox.Dock = DockStyle.Fill;
            _outputTextBox.ReadOnly = true;
            _outputTextBox.BackColor = Color.Black;
            _outputTextBox.ForeColor = Color.Lime;
            _outputTextBox.Font = new Font("Consolas", 11);
			   _outputTextBox.BorderStyle = BorderStyle.None;
				

            _inputTextBox.Dock = DockStyle.Bottom;
            _inputTextBox.BackColor = Color.Black;
            _inputTextBox.ForeColor = Color.White;
            _inputTextBox.Font = new Font("Consolas", 11);
            _inputTextBox.BorderStyle = BorderStyle.FixedSingle;
            _inputTextBox.Height = 30;
            _inputTextBox.PlaceholderText = "Введіть PowerShell команду та натисніть Enter...";

            _inputTextBox.KeyDown += async (sender, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    var command = _inputTextBox.Text.Trim();
                    if (!string.IsNullOrEmpty(command))
                    {
                        _inputTextBox.Clear();
                        _outputTextBox.AppendText($"PS> {command}\r\n");
						
								if (command.Equals("newTerminal", StringComparison.OrdinalIgnoreCase))
									{
										
										MainForm newForm = new MainForm();
										TerminalCount++;
										newForm.AppendOutput($"[Info] Створено новий термінал #{TerminalCount}\r\n\r\n");
										newForm.Show();

										e.Handled = true;
										e.SuppressKeyPress = true;
										return;
									}


                        if (command.StartsWith("changeColor ", StringComparison.OrdinalIgnoreCase))
                        {
                            string colorName = command.Substring("changeColor ".Length).Trim();
                            try
                            {
                                var newColor = Color.FromName(colorName);
                                if (newColor.IsKnownColor)
                                {
                                    _outputTextBox.BackColor = newColor;
                                    _outputTextBox.AppendText($"[Info] Колір змінено на {colorName}\r\n\r\n");
                                }
                                else
                                {
                                    _outputTextBox.AppendText($"[Error] Невідомий колір: {colorName}\r\n\r\n");
                                }
                            }
                            catch
                            {
                                _outputTextBox.AppendText($"[Error] Помилка при зміні кольору.\r\n\r\n");
                            }

                            e.Handled = true;
                            e.SuppressKeyPress = true;
                            return;
                        }
							if (command.StartsWith("Color", StringComparison.OrdinalIgnoreCase))
							{
								string colorName = command.Substring("Color ".Length).Trim();
								try
								{
									var newColor = Color.FromName(colorName);
									if (newColor.IsKnownColor)
									{
										_outputTextBox.ForeColor = newColor;
										_outputTextBox.AppendText($"[Info] Колір тексту змінено на {colorName}\r\n\r\n");
									}
									else
									{
										_outputTextBox.AppendText($"[Error] Невідомий колір: {colorName}\r\n\r\n");
									}
								}
								catch
								{
									_outputTextBox.AppendText($"[Error] Помилка при зміні кольору.\r\n\r\n");
								}
									 e.Handled = true;
                            e.SuppressKeyPress = true;
                            return;
								}
							

                        var result = await _interpreter.InterpretAsync(command);

                        if (result.Success && !string.IsNullOrEmpty(result.Output))
                            _outputTextBox.AppendText($"{result.Output}\r\n");
                        else if (!string.IsNullOrEmpty(result.Errors))
                            _outputTextBox.AppendText($"ПОМИЛКА: {result.Errors}\r\n");

                        _outputTextBox.AppendText("\r\n");
                        _outputTextBox.SelectionStart = _outputTextBox.Text.Length;
                        _outputTextBox.ScrollToCaret();
                    }
                    e.Handled = true;
                    e.SuppressKeyPress = true;
                }
            };

            this.Shown += (sender, e) => _inputTextBox.Focus();
            _outputTextBox.Click += (sender, e) => _inputTextBox.Focus();

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
