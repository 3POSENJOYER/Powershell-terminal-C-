using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using PowerShellTerminal.Application.Services;
using PowerShellTerminal.Domain.Entities;

namespace PowerShellTerminal
{
    public partial class MainForm : Form
    {
        private TabManager _tabManager;
        private ThemeManager _themeManager;
        private HistoryService _historyService;

        public MainForm()
        {
            InitializeComponent();

            _historyService = new HistoryService();
            _themeManager = new ThemeManager();
            _tabManager = new TabManager(tabControl, _themeManager, _historyService);

            this.Load += MainForm_Load;
        }

        private async void MainForm_Load(object sender, EventArgs e)
        {
            try
            {
                await _tabManager.CreateNewTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create initial terminal: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void newTerminalToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                await _tabManager.CreateNewTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create new terminal: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void lightThemeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _themeManager?.ApplyLightTheme();
        }

        private void darkThemeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _themeManager?.ApplyDarkTheme();
        }

        private void customThemeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (var colorDialog = new System.Windows.Forms.ColorDialog())
            using (var fontDialog = new System.Windows.Forms.FontDialog())
            {
                colorDialog.AllowFullOpen = true;
                colorDialog.FullOpen = true;
                colorDialog.Color = System.Drawing.Color.White;

                colorDialog.HelpRequest += (s, ev) => { };
                if (colorDialog.ShowDialog() != DialogResult.OK)
                    return;

                var background = colorDialog.Color;

                colorDialog.Color = System.Drawing.Color.Black;
                if (colorDialog.ShowDialog() != DialogResult.OK)
                    return;

                var foreground = colorDialog.Color;

                if (fontDialog.ShowDialog() != DialogResult.OK)
                    return;

                var font = fontDialog.Font;

                var theme = new PowerShellTerminal.Domain.Models.TerminalTheme
                {
                    BackgroundColor = background,
                    ForegroundColor = foreground,
                    ErrorColor = System.Drawing.Color.Red,
                    DefaultFont = font
                };

                _themeManager?.ApplyTheme(theme);
            }
        }
    }
}
