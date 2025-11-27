using PowerShellTerminal.Application.Services;
using PowerShellTerminal.Domain.Models;
using System.Windows.Forms;

namespace PowerShellTerminal.Application.Services
{
    public class TabManager
    {
        private TabControl _tabControl;
        private List<TerminalTab> _tabs;
        private ThemeManager _themeManager;
        private HistoryService _historyService;

        public TabManager(TabControl tabControl, ThemeManager themeManager, HistoryService historyService)
        {
            _tabControl = tabControl;
            _tabs = new List<TerminalTab>();
            _themeManager = themeManager;
            _historyService = historyService;
        }

        public async Task CreateNewTabAsync()
        {
            var session = await _historyService.StartNewSessionAsync();
            int sessionId = session?.Id ?? 0;

            var terminalTab = new TerminalTab(_themeManager, _historyService, sessionId);
            terminalTab.TabPage.Text = $"PowerShell {_tabs.Count + 1}";

            _tabControl.TabPages.Add(terminalTab.TabPage);
            _tabs.Add(terminalTab);
            _tabControl.SelectedTab = terminalTab.TabPage;

            terminalTab.ApplyTheme(_themeManager.GetCurrentTheme());
        }

        public void CloseCurrentTab()
        {
            if (_tabControl.TabPages.Count > 1)
            {
                var currentTab = _tabControl.SelectedTab;
                _tabControl.TabPages.Remove(currentTab);
                
                var tabToRemove = _tabs.FirstOrDefault(t => t.TabPage == currentTab);
                if (tabToRemove != null)
                {
                    // Detach from theme manager to avoid memory leaks / stale references
                    _themeManager?.Detach(tabToRemove);
                    _tabs.Remove(tabToRemove);
                }
            }
            else
            {
                MessageBox.Show("Cannot close the last tab.", "Information", 
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        public TerminalTab GetCurrentTab()
        {
            return _tabs.FirstOrDefault(t => t.TabPage == _tabControl.SelectedTab);
        }
    }
}