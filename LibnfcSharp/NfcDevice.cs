using LibnfcSharp.PInvoke;
using System;

namespace LibnfcSharp
{
    public class NfcDevice : IDisposable
    {
        public IntPtr DevicePointer { get; private set; }

        private bool _disposed = false;

        private string _name;
        public string Name
        {
            get
            {
                if (_name == null)
                    _name = Libnfc.DeviceGetName(DevicePointer);
                return _name;
            }
        }

        public NfcDevice(IntPtr devicePointer)
        {
            DevicePointer = devicePointer;
        }

        public bool AbortCommand()
        {
            var result = Libnfc.AbortCommand(DevicePointer);
            if (result < 0)
            {
                Perror("nfc_abort_command");
                return false;
            }
            return true;
        }

        public bool InitiatorInit()
        {
            var result = Libnfc.InitiatorInit(DevicePointer);
            if (result < 0)
            {
                Perror("nfc_initiator_init");
                return false;
            }
            return true;
        }

        public int InitiatorSelectPassiveTarget(NfcModulation modulation, byte[] abtUid, uint length, ref NfcTarget pnt) =>
            Libnfc.InitiatorSelectPassiveTarget(DevicePointer, modulation, abtUid, length, ref pnt);

        public bool DeviceSetPropertyBool(NfcProperty property, bool enable)
        {
            var result = Libnfc.DeviceSetPropertyBool(DevicePointer, property, enable);
            if (result < 0)
            {
                Perror("nfc_device_set_property_bool");
                return false;
            }
            return true;
        }

        public int InitiatorTransceiveBitsTimed(byte[] pbtTx, uint szTxBits, byte[] pbtTxPar, byte[] pbtRx, uint szRx, byte[] pbtRxPar, ref uint cycles) =>
            Libnfc.InitiatorTransceiveBitsTimed(DevicePointer, pbtTx, szTxBits, pbtTxPar, pbtRx, szRx, pbtRxPar, ref cycles);

        public int InitiatorTransceiveBits(byte[] pbtTx, uint szTxBits, byte[] pbtTxPar, byte[] pbtRx, uint szRx, byte[] pbtRxPar) =>
            Libnfc.InitiatorTransceiveBits(DevicePointer, pbtTx, szTxBits, pbtTxPar, pbtRx, szRx, pbtRxPar);

        public int InitiatorTransceiveBytesTimed(byte[] pbtTx, uint szTx, byte[] pbtRx, uint szRx, ref uint cycles) =>
            Libnfc.InitiatorTransceiveBytesTimed(DevicePointer, pbtTx, szTx, pbtRx, szRx, ref cycles);

        public int InitiatorTransceiveBytes(byte[] pbtTx, uint szTx, byte[] pbtRx, uint szRx, int timeout) =>
            Libnfc.InitiatorTransceiveBytes(DevicePointer, pbtTx, szTx, pbtRx, szRx, timeout);

        public void Iso14443aCrcAppend(byte[] pbtData, uint szLen) =>
            Libnfc.Iso14443aCrcAppend(pbtData, szLen);

        public void Perror(string s) =>
            Libnfc.Perror(DevicePointer, s);

        public void Close() => Dispose();

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources.
                    // component.Dispose();
                }
                Libnfc.Close(DevicePointer);
                DevicePointer = IntPtr.Zero;
                _disposed = true;
            }
        }

        ~NfcDevice()
        {
            Dispose(false);
        }
    }
}
