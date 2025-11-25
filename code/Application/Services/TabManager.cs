using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using PowerShellTerminal.Domain.Models;

namespace PowerShellTerminal.Application.Services
{
    public class TabManager
    {
        private readonly TabControl _tabControl;
        private readonly List<TerminalTab> _tabs;
        private readonly ThemeManager _themeManager;
        private readonly HistoryService _historyService;

        public TabManager(TabControl tabControl, ThemeManager themeManager, HistoryService historyService)
        {
            _tabControl = tabControl;
            _tabs = new List<TerminalTab>();
            _themeManager = themeManager;
            _historyService = historyService;
        }

        // Create a new terminal tab and add it to the tab control.
        public void CreateNewTab()
        {
            var terminalTab = new TerminalTab(_themeManager, _historyService)
            {
                Title = $"PowerShell {_tabs.Count + 1}"
            };
            terminalTab.TabPage.Text = terminalTab.Title;
            
            _tabControl.TabPages.Add(terminalTab.TabPage);
            _tabs.Add(terminalTab);
            _tabControl.SelectedTab = terminalTab.TabPage;
            terminalTab.ApplyTheme(_themeManager.GetCurrentTheme());
        }

        // Close the current tab (prevents closing the last tab).
        public void CloseCurrentTab()
        {
            if (_tabControl.TabPages.Count <= 1)
            {
                MessageBox.Show("Cannot close the last tab.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var currentTab = _tabControl.SelectedTab;
            var tabToRemove = _tabs.FirstOrDefault(t => t.TabPage == currentTab);
            
            if (tabToRemove != null)
            {
                _tabs.Remove(tabToRemove);
                _tabControl.TabPages.Remove(currentTab);
            }
        }

        // Get the currently active terminal tab.
        public TerminalTab GetCurrentTab()
        {
            return _tabs.FirstOrDefault(t => t.TabPage == _tabControl.SelectedTab);
        }
    }
}