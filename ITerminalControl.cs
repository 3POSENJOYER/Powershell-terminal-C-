using System;
using System.Drawing;
using System.Windows.Forms;

public interface ITerminalControl
{
    string GetText();
    void SetBackgroundColor(Color color);
    void SetForegroundColor(Color color);
    void SetFont(Font font);
    event EventHandler<string> CommandEntered;
    void WriteLine(string text, Color color);
    void Clear();
    Control AsControl();
}

public class SimpleTerminalControl : UserControl, ITerminalControl
{
    private readonly RichTextBox _outputBox;
    private readonly TextBox _inputBox;
    
    public event EventHandler<string> CommandEntered = (s, e) => { };
    
    public SimpleTerminalControl()
    {
        _outputBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Lime,
            Font = new Font("Consolas", 10),
            BorderStyle = BorderStyle.None
        };
        
        _inputBox = new TextBox
        {
            Dock = DockStyle.Bottom,
            BackColor = Color.Black,
            ForeColor = Color.White,
            Font = new Font("Consolas", 10),
            Height = 25
        };
        
        _inputBox.KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                CommandEntered?.Invoke(this, _inputBox.Text);
                _inputBox.Clear();
                e.Handled = e.SuppressKeyPress = true;
            }
        };
        
        Controls.Add(_outputBox);
        Controls.Add(_inputBox);
    }
    
    public string GetText() => _outputBox.Text;
    
    public void SetBackgroundColor(Color color)
    {
        _outputBox.BackColor = color;
        _inputBox.BackColor = color;
        BackColor = color;
    }
    
    public void SetForegroundColor(Color color)
    {
        _outputBox.ForeColor = color;
        ForeColor = color;
    }
    
    public void SetFont(Font font)
    {
        _outputBox.Font = font;
        _inputBox.Font = font;
        Font = font;
    }
    
    public void WriteLine(string text, Color color)
    {
        _outputBox.SelectionStart = _outputBox.TextLength;
        _outputBox.SelectionColor = color;
        _outputBox.AppendText(text + "\n");
        _outputBox.SelectionColor = _outputBox.ForeColor;
        _outputBox.ScrollToCaret();
    }
    
    public void Clear()
    {
        _outputBox.Clear();
    }
    
    public Control AsControl() => this;
}