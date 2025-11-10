using System;
using System.Drawing;
using System.Windows.Forms;

namespace PowerShellTerminal
{
    public class MainForm : Form
    {
        private readonly ITerminalFactory _factory;
        private TabControl _tabControl;
        private MenuStrip _menuStrip;
        private static int _terminalCount = 1;
        
        public MainForm()
        {
            _factory = new DarkTerminalFactory();
            _tabControl = new TabControl();
            _menuStrip = new MenuStrip();
            
            InitializeComponent();
            CreateNewTab();
        }
        
        public MainForm(ITerminalFactory factory)
        {
            _factory = factory;
            _tabControl = new TabControl();
            _menuStrip = new MenuStrip();
            
            InitializeComponent();
            CreateNewTab();
        }
        
        private void InitializeComponent()
        {
            Text = $"PowerShell Terminal - Master";
            Size = new Size(900, 700);
            StartPosition = FormStartPosition.CenterScreen;
            
            CreateMenu();
            CreateTabControl();
        }
        
        private void CreateMenu()
        {
            var fileMenu = new ToolStripMenuItem("File");
            fileMenu.DropDownItems.Add("New Tab", null, (s, e) => CreateNewTab());
            fileMenu.DropDownItems.Add("New Window", null, (s, e) => CreateNewWindow());
            fileMenu.DropDownItems.Add("Close Tab", null, (s, e) => CloseCurrentTab());
            fileMenu.DropDownItems.Add("-");
            fileMenu.DropDownItems.Add("Exit", null, (s, e) => Close());
            
            var viewMenu = new ToolStripMenuItem("View");
            viewMenu.DropDownItems.Add("Split Horizontal", null, (s, e) => SplitHorizontal());
            viewMenu.DropDownItems.Add("Split Vertical", null, (s, e) => SplitVertical());
            viewMenu.DropDownItems.Add("Dark Theme", null, (s, e) => ApplyTheme(new DarkTheme()));
            viewMenu.DropDownItems.Add("Light Theme", null, (s, e) => ApplyTheme(new LightTheme()));
            
            var settingsMenu = new ToolStripMenuItem("Settings");
            settingsMenu.DropDownItems.Add("Font Size +", null, (s, e) => ChangeFontSize(2));
            settingsMenu.DropDownItems.Add("Font Size -", null, (s, e) => ChangeFontSize(-2));
            settingsMenu.DropDownItems.Add("Background Color", null, (s, e) => ChangeBackgroundColor());
            settingsMenu.DropDownItems.Add("Text Color", null, (s, e) => ChangeTextColor());
            
            _menuStrip.Items.AddRange(new[] { fileMenu, viewMenu, settingsMenu });
            Controls.Add(_menuStrip);
            MainMenuStrip = _menuStrip;
        }
        
        private void CreateTabControl()
        {
            _tabControl.Dock = DockStyle.Fill;
            _tabControl.Location = new Point(0, _menuStrip.Height);
            Controls.Add(_tabControl);
        }
        
        private void CreateNewTab()
        {
            var terminalControl = _factory.CreateTerminalControl();
            var interpreter = _factory.CreateInterpreter();
            var theme = _factory.CreateTheme();
            
            var tabPage = new TabPage($"Terminal {_tabControl.TabCount + 1}");
            
            terminalControl.SetBackgroundColor(theme.BackgroundColor);
            terminalControl.SetForegroundColor(theme.ForegroundColor);
            terminalControl.SetFont(theme.DefaultFont);
            
            terminalControl.CommandEntered += async (s, cmd) => 
            {
                if (cmd.Equals("new", StringComparison.OrdinalIgnoreCase))
                {
                    CreateNewTab();
                    return;
                }
                
                if (cmd.Equals("clear", StringComparison.OrdinalIgnoreCase))
                {
                    terminalControl.Clear();
                    return;
                }
                
                var result = await interpreter.InterpretAsync(cmd);
                var color = result.Success ? theme.SuccessColor : theme.ErrorColor;
                
                if (result.Success && !string.IsNullOrEmpty(result.Output))
                    terminalControl.WriteLine(result.Output, theme.ForegroundColor);
                else if (!string.IsNullOrEmpty(result.Errors))
                    terminalControl.WriteLine($"ERROR: {result.Errors}", color);
            };
            
            var control = terminalControl.AsControl();
            control.Dock = DockStyle.Fill;
            tabPage.Controls.Add(control);
            
            _tabControl.TabPages.Add(tabPage);
            _tabControl.SelectedTab = tabPage;
            
          
            control.Focus();
        }
        
        private void CreateNewWindow()
        {
            _terminalCount++;
            var newForm = new MainForm(_factory)
            {
                Text = $"PowerShell Terminal - Window {_terminalCount}"
            };
            newForm.Show();
        }
        
        private void CloseCurrentTab()
        {
            if (_tabControl.TabCount > 1 && _tabControl.SelectedTab != null)
            {
                _tabControl.TabPages.Remove(_tabControl.SelectedTab);
            }
            else if (_tabControl.TabCount == 1)
            {
                MessageBox.Show("Cannot close the last tab");
            }
        }
        
        private void SplitHorizontal()
        {
            if (_tabControl.SelectedTab != null)
            {
                var splitContainer = new SplitContainer
                {
                    Dock = DockStyle.Fill,
                    Orientation = Orientation.Horizontal
                };
                
                var originalControl = _tabControl.SelectedTab.Controls[0];
                _tabControl.SelectedTab.Controls.Remove(originalControl);
                
               
                var newTerminal = _factory.CreateTerminalControl();
                var newControl = newTerminal.AsControl();
                newControl.Dock = DockStyle.Fill;
                
                splitContainer.Panel1.Controls.Add(originalControl);
                splitContainer.Panel2.Controls.Add(newControl);
                
                _tabControl.SelectedTab.Controls.Add(splitContainer);
            }
        }
        
        private void SplitVertical()
        {
            if (_tabControl.SelectedTab != null)
            {
                var splitContainer = new SplitContainer
                {
                    Dock = DockStyle.Fill,
                    Orientation = Orientation.Vertical
                };
                
                var originalControl = _tabControl.SelectedTab.Controls[0];
                _tabControl.SelectedTab.Controls.Remove(originalControl);
                
                
                var newTerminal = _factory.CreateTerminalControl();
                var newControl = newTerminal.AsControl();
                newControl.Dock = DockStyle.Fill;
                
                splitContainer.Panel1.Controls.Add(originalControl);
                splitContainer.Panel2.Controls.Add(newControl);
                
                _tabControl.SelectedTab.Controls.Add(splitContainer);
            }
        }
        
        private void ApplyTheme(ITerminalTheme theme)
        {
            foreach (TabPage tabPage in _tabControl.TabPages)
            {
                foreach (Control control in tabPage.Controls)
                {
                    if (control is SplitContainer splitContainer)
                    {
                        ApplyThemeToSplitContainer(splitContainer, theme);
                    }
                    else if (control is ITerminalControl terminal)
                    {
                        terminal.SetBackgroundColor(theme.BackgroundColor);
                        terminal.SetForegroundColor(theme.ForegroundColor);
                        terminal.SetFont(theme.DefaultFont);
                    }
                }
            }
        }
        
        private void ApplyThemeToSplitContainer(SplitContainer container, ITerminalTheme theme)
        {
            foreach (Control control in container.Panel1.Controls)
            {
                if (control is ITerminalControl terminal)
                {
                    terminal.SetBackgroundColor(theme.BackgroundColor);
                    terminal.SetForegroundColor(theme.ForegroundColor);
                    terminal.SetFont(theme.DefaultFont);
                }
            }
            
            foreach (Control control in container.Panel2.Controls)
            {
                if (control is ITerminalControl terminal)
                {
                    terminal.SetBackgroundColor(theme.BackgroundColor);
                    terminal.SetForegroundColor(theme.ForegroundColor);
                    terminal.SetFont(theme.DefaultFont);
                }
            }
        }
        
        private void ChangeFontSize(int delta)
        {
            foreach (TabPage tabPage in _tabControl.TabPages)
            {
                foreach (Control control in tabPage.Controls)
                {
                    if (control is SplitContainer splitContainer)
                    {
                        ChangeFontSizeInSplitContainer(splitContainer, delta);
                    }
                    else if (control is ITerminalControl terminal)
                    {
                        var currentFont = terminal.AsControl().Font;
                        terminal.SetFont(new Font(currentFont.FontFamily, Math.Max(8, currentFont.Size + delta)));
                    }
                }
            }
        }
        
        private void ChangeFontSizeInSplitContainer(SplitContainer container, int delta)
        {
            foreach (Control control in container.Panel1.Controls)
            {
                if (control is ITerminalControl terminal)
                {
                    var currentFont = terminal.AsControl().Font;
                    terminal.SetFont(new Font(currentFont.FontFamily, Math.Max(8, currentFont.Size + delta)));
                }
            }
            
            foreach (Control control in container.Panel2.Controls)
            {
                if (control is ITerminalControl terminal)
                {
                    var currentFont = terminal.AsControl().Font;
                    terminal.SetFont(new Font(currentFont.FontFamily, Math.Max(8, currentFont.Size + delta)));
                }
            }
        }
        
        private void ChangeBackgroundColor()
        {
            var colorDialog = new ColorDialog();
            if (colorDialog.ShowDialog() == DialogResult.OK)
            {
                foreach (TabPage tabPage in _tabControl.TabPages)
                {
                    foreach (Control control in tabPage.Controls)
                    {
                        if (control is ITerminalControl terminal)
                        {
                            terminal.SetBackgroundColor(colorDialog.Color);
                        }
                    }
                }
            }
        }
        
        private void ChangeTextColor()
        {
            var colorDialog = new ColorDialog();
            if (colorDialog.ShowDialog() == DialogResult.OK)
            {
                foreach (TabPage tabPage in _tabControl.TabPages)
                {
                    foreach (Control control in tabPage.Controls)
                    {
                        if (control is ITerminalControl terminal)
                        {
                            terminal.SetForegroundColor(colorDialog.Color);
                        }
                    }
                }
            }
        }
    }
}