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
        private Infrastructure.Repositories.UserSettingsRepository _settingsRepo;
        private Domain.Entities.UserSettings _userSettings;

        public MainForm()
        {
            InitializeComponent();

            _historyService = new HistoryService();
            _themeManager = new ThemeManager();
            _tabManager = new TabManager(tabControl, _themeManager, _historyService);
            _settingsRepo = new Infrastructure.Repositories.UserSettingsRepository();
            this.Load += MainForm_Load;
            this.FormClosing += MainForm_FormClosing;
        }

        private async void MainForm_Load(object sender, EventArgs e)
        {
            try
            {
                    try
                    {
                        _userSettings = await _settingsRepo.GetUserSettingsAsync();
                        if (_userSettings != null)
                        {
                            _themeManager.ApplyTheme(_userSettings);
                            if (_userSettings.WindowWidth > 0 && _userSettings.WindowHeight > 0)
                            {
                                this.Width = _userSettings.WindowWidth;
                                this.Height = _userSettings.WindowHeight;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to load user settings: {ex.Message}", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }

                    await _tabManager.CreateNewTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create initial terminal: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

            private async void MainForm_FormClosing(object sender, FormClosingEventArgs e)
            {
                try
                {
                    if (_userSettings == null)
                        _userSettings = await _settingsRepo.GetUserSettingsAsync();

                    _userSettings.WindowWidth = this.Width;
                    _userSettings.WindowHeight = this.Height;
                    _userSettings.LastModified = DateTime.UtcNow;
                    await _settingsRepo.SaveUserSettingsAsync(_userSettings);
                }
                catch { }
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

        private async void lightThemeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _themeManager?.ApplyLightTheme();
            try
            {
                if (_userSettings == null)
                    _userSettings = await _settingsRepo.GetUserSettingsAsync();

                _userSettings.ThemeName = "Light";
                _userSettings.BackgroundColor = "#FFFFFF";
                _userSettings.ForegroundColor = "#000000";
                _userSettings.FontFamily = _themeManager.GetCurrentTheme().DefaultFont?.FontFamily.Name ?? _userSettings.FontFamily;
                _userSettings.FontSize = (int)Math.Round(_themeManager.GetCurrentTheme().DefaultFont?.Size ?? _userSettings.FontSize);
                _userSettings.LastModified = DateTime.UtcNow;
                await _settingsRepo.SaveUserSettingsAsync(_userSettings);
            }
            catch { }
        }

        private async void darkThemeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _themeManager?.ApplyDarkTheme();
            try
            {
                if (_userSettings == null)
                    _userSettings = await _settingsRepo.GetUserSettingsAsync();

                _userSettings.ThemeName = "Dark";
                var bg = _themeManager.GetCurrentTheme().BackgroundColor;
                var fg = _themeManager.GetCurrentTheme().ForegroundColor;
                _userSettings.BackgroundColor = $"#{bg.R:X2}{bg.G:X2}{bg.B:X2}";
                _userSettings.ForegroundColor = $"#{fg.R:X2}{fg.G:X2}{fg.B:X2}";
                _userSettings.FontFamily = _themeManager.GetCurrentTheme().DefaultFont?.FontFamily.Name ?? _userSettings.FontFamily;
                _userSettings.FontSize = (int)Math.Round(_themeManager.GetCurrentTheme().DefaultFont?.Size ?? _userSettings.FontSize);
                _userSettings.LastModified = DateTime.UtcNow;
                await _settingsRepo.SaveUserSettingsAsync(_userSettings);
            }
            catch { }
        }



        private async void customThemeToolStripMenuItem_Click(object sender, EventArgs e)
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

                try
                {
                    if (_userSettings == null)
                        _userSettings = await _settingsRepo.GetUserSettingsAsync();

                    _userSettings.ThemeName = "Custom";
                    _userSettings.BackgroundColor = $"#{background.R:X2}{background.G:X2}{background.B:X2}";
                    _userSettings.ForegroundColor = $"#{foreground.R:X2}{foreground.G:X2}{foreground.B:X2}";
                    _userSettings.FontFamily = font.FontFamily.Name;
                    _userSettings.FontSize = (int)Math.Round(font.Size);
                    _userSettings.LastModified = DateTime.UtcNow;
                    await _settingsRepo.SaveUserSettingsAsync(_userSettings);
                }
                catch { }
            }
        }
    }
}
