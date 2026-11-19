using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

class KothFullscreenLauncher : Form {
    [DllImport("dwmapi.dll")]
    static extern int DwmRegisterThumbnail(IntPtr dest, IntPtr src, out IntPtr thumb);
    [DllImport("dwmapi.dll")]
    static extern int DwmUnregisterThumbnail(IntPtr thumb);
    [DllImport("dwmapi.dll")]
    static extern int DwmUpdateThumbnailProperties(IntPtr thumb, ref DWM_THUMBNAIL_PROPERTIES props);

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")]
    static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);
    [DllImport("user32.dll")]
    static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll")]
    static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
    [DllImport("user32.dll")]
    static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern bool EnumChildWindows(IntPtr hWnd, EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll")]
    static extern uint MapVirtualKey(uint uCode, uint uMapType);

    [StructLayout(LayoutKind.Sequential)]
    struct DWM_THUMBNAIL_PROPERTIES {
        public int dwFlags;
        public RECT rcDestination;
        public RECT rcSource;
        public byte opacity;
        public bool fVisible;
        public bool fSourceClientAreaOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left, Top, Right, Bottom;
        public RECT(int l, int t, int r, int b) { Left = l; Top = t; Right = r; Bottom = b; }
    }

    const int DWM_TNP_RECTDESTINATION = 0x00000001;
    const int DWM_TNP_OPACITY = 0x00000004;
    const int DWM_TNP_VISIBLE = 0x00000008;
    const int DWM_TNP_SOURCECLIENTAREAONLY = 0x00000010;

    const int GWL_STYLE = -16;
    const int GWL_EXSTYLE = -20;
    const int WS_CHILD = 0x40000000;
    const int WS_POPUP = unchecked((int)0x80000000);
    const int WS_OVERLAPPEDWINDOW = 0x00CF0000;
    const int WS_EX_DLGMODALFRAME = 0x00000001;
    const int WS_EX_WINDOWEDGE = 0x00000100;
    const int WS_EX_CLIENTEDGE = 0x00000200;
    const int WS_EX_STATICEDGE = 0x00020000;
    const uint SWP_NOSIZE = 0x0001;
    const uint SWP_NOACTIVATE = 0x0010;
    const uint SWP_FRAMECHANGED = 0x0020;
    const uint SWP_SHOWWINDOW = 0x0040;

    const uint WM_MOUSEMOVE = 0x0200;
    const uint WM_LBUTTONDOWN = 0x0201;
    const uint WM_LBUTTONUP = 0x0202;
    const uint WM_RBUTTONDOWN = 0x0204;
    const uint WM_RBUTTONUP = 0x0205;
    const uint WM_KEYDOWN = 0x0100;
    const uint WM_KEYUP = 0x0101;
    const uint WM_CHAR = 0x0102;

    IntPtr thumb = IntPtr.Zero;
    IntPtr currentGameHwnd = IntPtr.Zero;
    readonly bool windowedMode;
    int screenW, screenH;
    int dstX, dstY, dstW, dstH;
    int missingTicks = 0;
    System.Windows.Forms.Timer pollTimer;

    public KothFullscreenLauncher(bool windowed, string windowTitle) {
        this.windowedMode = windowed;
        this.StartPosition = FormStartPosition.Manual;
        this.BackColor = Color.Black;

        Rectangle bounds = Screen.PrimaryScreen.Bounds;
        this.screenW = bounds.Width;
        this.screenH = bounds.Height;

        if (windowedMode) {
            this.Text = string.IsNullOrEmpty(windowTitle) ? "King of the Hill" : windowTitle;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.TopMost = false;
            this.Location = new Point(0, 0);
            this.ClientSize = new Size(640, 480);
            dstX = 0;
            dstY = 0;
            dstW = 640;
            dstH = 480;
        } else {
            this.Text = "KOTH_FULLSCREEN_HOST";
            this.FormBorderStyle = FormBorderStyle.None;
            this.Location = new Point(0, 0);
            this.Size = new Size(screenW, screenH);
            this.TopMost = true;

            // Calculate 4:3 pillarboxed target rect
            dstH = screenH;
            dstW = (int)(screenH * (4.0 / 3.0));
            if (dstW > screenW) {
                dstW = screenW;
                dstH = (int)(screenW * (3.0 / 4.0));
            }
            dstX = (screenW - dstW) / 2;
            dstY = (screenH - dstH) / 2;
        }
    }

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);
        if (windowedMode) {
            int stageX = (screenW - 640) / 2;
            int stageY = (screenH - 480) / 2;
            Point curClient = this.PointToScreen(Point.Empty);
            this.Location = new Point(this.Location.X + (stageX - curClient.X), this.Location.Y + (stageY - curClient.Y));
        }
    }

    protected override void OnLocationChanged(EventArgs e) {
        base.OnLocationChanged(e);
        if (windowedMode && IsWindow(currentGameHwnd)) {
            Point clientOrigin = this.PointToScreen(Point.Empty);
            SetWindowPos(currentGameHwnd, new IntPtr(1), clientOrigin.X, clientOrigin.Y, 640, 480, SWP_SHOWWINDOW | SWP_NOACTIVATE);
        }
    }

    void AttachGameWindow(IntPtr gameHwnd, IntPtr backdropHwnd) {
        if (gameHwnd == IntPtr.Zero || gameHwnd == currentGameHwnd) return;

        if (thumb != IntPtr.Zero) {
            DwmUnregisterThumbnail(thumb);
            thumb = IntPtr.Zero;
        }

        currentGameHwnd = gameHwnd;

        // Unparent child window and strip borders so client (0,0) aligns cleanly for DWM and WINMM mapping
        SetParent(gameHwnd, IntPtr.Zero);
        int style = GetWindowLong(gameHwnd, GWL_STYLE);
        style = (style & ~(WS_CHILD | WS_OVERLAPPEDWINDOW)) | WS_POPUP;
        SetWindowLong(gameHwnd, GWL_STYLE, style);

        int exStyle = GetWindowLong(gameHwnd, GWL_EXSTYLE);
        exStyle &= ~(WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE);
        SetWindowLong(gameHwnd, GWL_EXSTYLE, exStyle);

        // Hide backdrop if present
        if (backdropHwnd != IntPtr.Zero) {
            ShowWindow(backdropHwnd, 0);
        }

        // Position borderless 640x480 stage aligned with WINMM.dll's (stageX, stageY) or client origin beneath host
        Point targetPos = windowedMode ? this.PointToScreen(Point.Empty) : new Point((screenW - 640) / 2, (screenH - 480) / 2);
        SetWindowPos(gameHwnd, new IntPtr(1), targetPos.X, targetPos.Y, 640, 480, SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_FRAMECHANGED);

        // Register DWM thumbnail
        int hr = DwmRegisterThumbnail(this.Handle, currentGameHwnd, out thumb);
        if (hr == 0 && thumb != IntPtr.Zero) {
            DWM_THUMBNAIL_PROPERTIES props = new DWM_THUMBNAIL_PROPERTIES();
            props.dwFlags = DWM_TNP_RECTDESTINATION | DWM_TNP_VISIBLE | DWM_TNP_OPACITY | DWM_TNP_SOURCECLIENTAREAONLY;
            props.rcDestination = new RECT(dstX, dstY, dstX + dstW, dstY + dstH);
            props.opacity = 255;
            props.fVisible = true;
            props.fSourceClientAreaOnly = true;
            DwmUpdateThumbnailProperties(thumb, ref props);
        }

        // Schedule auto-advance past title card after 1.5s
        var tAdv = new System.Windows.Forms.Timer();
        tAdv.Interval = 1500;
        tAdv.Tick += (s, e) => {
            tAdv.Stop();
            if (IsWindow(currentGameHwnd)) {
                PostMessage(currentGameHwnd, WM_CHAR, (IntPtr)0x0D, IntPtr.Zero);
            }
        };
        tAdv.Start();
    }

    Point MapToGame(int x, int y) {
        if (x < dstX) x = dstX;
        if (x >= dstX + dstW) x = dstX + dstW - 1;
        if (y < dstY) y = dstY;
        if (y >= dstY + dstH) y = dstY + dstH - 1;
        int gx = (x - dstX) * 640 / dstW;
        int gy = (y - dstY) * 480 / dstH;
        return new Point(gx, gy);
    }

    IntPtr MakeLParam(int x, int y) {
        return (IntPtr)((y << 16) | (x & 0xFFFF));
    }

    protected override void OnMouseMove(MouseEventArgs e) {
        if (IsWindow(currentGameHwnd)) {
            Point g = MapToGame(e.X, e.Y);
            PostMessage(currentGameHwnd, WM_MOUSEMOVE, (IntPtr)0, MakeLParam(g.X, g.Y));
        }
        base.OnMouseMove(e);
    }

    protected override void OnMouseDown(MouseEventArgs e) {
        if (IsWindow(currentGameHwnd)) {
            Point g = MapToGame(e.X, e.Y);
            uint msg = (e.Button == MouseButtons.Right) ? WM_RBUTTONDOWN : WM_LBUTTONDOWN;
            IntPtr wParam = (e.Button == MouseButtons.Right) ? (IntPtr)2 : (IntPtr)1;
            PostMessage(currentGameHwnd, msg, wParam, MakeLParam(g.X, g.Y));
        }
        base.OnMouseDown(e);
    }

    protected override void OnMouseUp(MouseEventArgs e) {
        if (IsWindow(currentGameHwnd)) {
            Point g = MapToGame(e.X, e.Y);
            uint msg = (e.Button == MouseButtons.Right) ? WM_RBUTTONUP : WM_LBUTTONUP;
            PostMessage(currentGameHwnd, msg, (IntPtr)0, MakeLParam(g.X, g.Y));
        }
        base.OnMouseUp(e);
    }

    protected override bool IsInputKey(Keys keyData) {
        return true;
    }

    protected override void OnKeyDown(KeyEventArgs e) {
        if (IsWindow(currentGameHwnd)) {
            // Director (IML32.dll) handles printable characters, Backspace, Enter, and Esc via WM_CHAR,
            // and only uses WM_KEYDOWN for VK_TAB (0x09) and non-character keys (MapVirtualKey == 0) or Ctrl combos.
            // Not posting WM_KEYDOWN for character keys prevents Proj.dll's TranslateMessage from generating a second WM_CHAR.
            uint mappedChar = MapVirtualKey((uint)e.KeyValue, 2);
            if (e.KeyCode == Keys.Tab || mappedChar == 0 || e.Control) {
                PostMessage(currentGameHwnd, WM_KEYDOWN, (IntPtr)e.KeyValue, IntPtr.Zero);
            }
        }
        base.OnKeyDown(e);
    }

    protected override void OnKeyUp(KeyEventArgs e) {
        if (IsWindow(currentGameHwnd)) {
            uint mappedChar = MapVirtualKey((uint)e.KeyValue, 2);
            if (e.KeyCode == Keys.Tab || mappedChar == 0 || e.Control) {
                PostMessage(currentGameHwnd, WM_KEYUP, (IntPtr)e.KeyValue, IntPtr.Zero);
            }
        }
        base.OnKeyUp(e);
    }

    protected override void OnKeyPress(KeyPressEventArgs e) {
        if (IsWindow(currentGameHwnd)) {
            if (e.KeyChar != '\t') {
                PostMessage(currentGameHwnd, WM_CHAR, (IntPtr)e.KeyChar, IntPtr.Zero);
            }
        }
        base.OnKeyPress(e);
    }

    static bool IsAnyKothProcessRunning() {
        foreach (Process p in Process.GetProcesses()) {
            try {
                string n = p.ProcessName.ToLowerInvariant();
                if ((n == "koth_menu" || n == "hootpc" || n == "hoot" || n == "thuntpc") && !p.HasExited) {
                    return true;
                }
            } catch { }
        }
        return false;
    }

    static void FindActiveGameWindows(out IntPtr outChild, out IntPtr outBackdrop) {
        IntPtr child = IntPtr.Zero;
        IntPtr backdrop = IntPtr.Zero;

        EnumWindows((hWnd, lp) => {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            try {
                Process p = Process.GetProcessById((int)pid);
                string n = p.ProcessName.ToLowerInvariant();
                if (n == "koth_menu" || n == "hootpc" || n == "hoot" || n == "thuntpc") {
                    StringBuilder sb = new StringBuilder(64);
                    GetClassName(hWnd, sb, 64);
                    string cls = sb.ToString();
                    if (cls == "ImlWinBackdropClass") {
                        backdrop = hWnd;
                        EnumChildWindows(hWnd, (ch, lp2) => {
                            StringBuilder csb = new StringBuilder(64);
                            GetClassName(ch, csb, 64);
                            if (csb.ToString() == "ImlWinCls") {
                                child = ch;
                                return false;
                            }
                            return true;
                        }, IntPtr.Zero);
                    } else if (cls == "ImlWinCls") {
                        child = hWnd;
                    }
                    if (child != IntPtr.Zero) return false;
                }
            } catch { }
            return true;
        }, IntPtr.Zero);

        outChild = child;
        outBackdrop = backdrop;
    }

    protected override void OnShown(EventArgs e) {
        base.OnShown(e);

        pollTimer = new System.Windows.Forms.Timer();
        pollTimer.Interval = 200;
        pollTimer.Tick += (s, ev) => {
            IntPtr child, backdrop;
            FindActiveGameWindows(out child, out backdrop);

            if (child != IntPtr.Zero) {
                missingTicks = 0;
                if (child != currentGameHwnd || thumb == IntPtr.Zero) {
                    AttachGameWindow(child, backdrop);
                }
            } else if (IsAnyKothProcessRunning()) {
                missingTicks = 0;
            } else {
                missingTicks++;
                if (missingTicks >= 15) { // 3 seconds without process -> exit
                    pollTimer.Stop();
                    this.Close();
                }
            }
        };
        pollTimer.Start();
    }

    public static void KillExistingGameProcesses(bool waitForExit) {
        foreach (Process p in Process.GetProcesses()) {
            try {
                string n = p.ProcessName.ToLowerInvariant();
                if (n == "koth_menu" || n == "hootpc" || n == "hoot" || n == "thuntpc") {
                    p.Kill();
                    if (waitForExit) {
                        p.WaitForExit(2000);
                    }
                }
            } catch { }
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e) {
        if (pollTimer != null) pollTimer.Stop();
        if (thumb != IntPtr.Zero) {
            DwmUnregisterThumbnail(thumb);
            thumb = IntPtr.Zero;
        }

        KillExistingGameProcesses(false);
        base.OnFormClosing(e);
    }
}

class Program {
    [STAThread]
    static void Main(string[] args) {
        bool windowed = false;
        string windowTitle = "King of the Hill";
        string exePath = null;
        for (int i = 0; i < args.Length; i++) {
            string a = args[i];
            string lower = a.ToLowerInvariant();
            if (lower == "--windowed" || lower == "-windowed" || lower == "/windowed") {
                windowed = true;
            } else if ((lower == "--title" || lower == "-title") && i + 1 < args.Length) {
                windowTitle = args[++i];
            } else if (exePath == null) {
                exePath = a;
            }
        }

        if (exePath == null) {
            Console.WriteLine("Usage: KOTH_Fullscreen_Launcher.exe [--windowed] [--title <title>] <path_to_game_exe>");
            return;
        }

        KothFullscreenLauncher.KillExistingGameProcesses(true);

        string workingDir = System.IO.Path.GetDirectoryName(exePath);
        Process.Start(new ProcessStartInfo(exePath) { WorkingDirectory = workingDir });

        Application.EnableVisualStyles();
        Application.Run(new KothFullscreenLauncher(windowed, windowTitle));
    }
}
