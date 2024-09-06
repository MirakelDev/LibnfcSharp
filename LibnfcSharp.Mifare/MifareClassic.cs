using LibnfcSharp.Mifare.Enums;
using LibnfcSharp.PInvoke;
using System;
using System.Linq;

namespace LibnfcSharp.Mifare
{
    public partial class MifareClassic
    {
        public const byte UID_SIZE = 4;
        public const byte KEY_SIZE = 6;
        public const byte BLOCK_SIZE = 16;
        public const byte SECTOR_COUNT = 16;
        public const byte BLOCKS_PER_SECTOR = 4;
        public const byte BLOCKS_TOTAL_COUNT = BLOCKS_PER_SECTOR * SECTOR_COUNT;

        public static readonly byte[] FACTORY_KEY = new byte[KEY_SIZE] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        public static readonly byte[] EMPTY_BLOCK = new byte[BLOCK_SIZE] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        private byte[] _rxBuffer = new byte[264];
        private NfcDevice _device;
        private NfcTarget _target;
        private Func<byte, byte[], byte[]> _keyAProviderCallback;

        private MifareMagicCardType _magicCardType = MifareMagicCardType.NONE;
        public MifareMagicCardType MagicCardType { get { return _magicCardType; } }
        public byte[] Uid { get { return _target.TargetInfo.Iso14443aInfo.abtUid.Take(UID_SIZE).ToArray(); } }

        public MifareClassic(NfcDevice device)
        {
            _target = new NfcTarget();
            _device = device;
        }

        public void RegisterKeyAProviderCallback(Func<byte, byte[], byte[]> keyAProviderCallback) =>
            _keyAProviderCallback = keyAProviderCallback;

        public void InitialDevice()
        {
            // Initialise NFC device as "initiator"
            _device.InitiatorInit();
            // Let the reader only try once to find a tag
            _device.DeviceSetPropertyBool(NfcProperty.InfiniteSelect, false);
            // Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
            _device.DeviceSetPropertyBool(NfcProperty.AutoIso14443_4, false);
        }

        public bool SelectCard()
        {
            var modulation = new NfcModulation
            {
                ModulationType = NfcModulationType.NMT_ISO14443A,
                BaudRate = NfcBaudRate.NBR_106
            };

            return _device.InitiatorSelectPassiveTarget(modulation, null, 0, ref _target) > 0;
        }

        public void WaitForCard()
        {
            while (!SelectCard());
        }

        public void IdentifyMagicCardType()
        {
            _magicCardType = MifareMagicCardType.NONE;

            if (!UnlockCard(out _magicCardType))
            {
                // Reselect card
                InitialDevice();
                WaitForCard();

                _magicCardType = IsMagicGen2()
                    ? MifareMagicCardType.GEN_2
                    : MifareMagicCardType.NONE;
            }
        }

        public bool ReadManufacturerBlock(out byte[] blockData)
        {
            blockData = new byte[16];

            if (MagicCardType == MifareMagicCardType.NONE ||
                MagicCardType == MifareMagicCardType.GEN_2)
            {
                if (!Authenticate(0, MifareKeyType.KEY_A, FACTORY_KEY) &&
                    !Authenticate(0, MifareKeyType.KEY_A, _keyAProviderCallback?.Invoke(0, Uid)))
                {
                    return false;
                }

            }

            return ReadBlock(0, out blockData);
        }

        public bool UnlockCard(out MifareMagicCardType magicCardType)
        {
            magicCardType = MifareMagicCardType.NONE;

            byte[] abtHalt = { 0x50, 0x00, 0x00, 0x00 };

            // special unlock command
            byte[] abtUnlock1 = { 0x40 };
            byte[] abtUnlock2 = { 0x43 };

            // Configure the CRC
            if (!_device.DeviceSetPropertyBool(NfcProperty.HandleCrc, false))
            {
                _device.Perror("nfc_configure");
                return false;
            }

            // Use raw send/receive methods
            if (!_device.DeviceSetPropertyBool(NfcProperty.EasyFraming, false))
            {
                _device.Perror("nfc_configure");
                return false;
            }

            _device.Iso14443aCrcAppend(abtHalt, 2);
            _device.InitiatorTransceiveBytes(abtHalt, 4, _rxBuffer, (uint)_rxBuffer.Length, 0); //transmit_bytes(abtHalt, 4);

            // now send unlock1 => Gen1B
            if (_device.InitiatorTransceiveBits(abtUnlock1, 7, null, _rxBuffer, (uint)_rxBuffer.Length, null) > 0 && _rxBuffer[0] == (byte)MifareResponseType.ACK) // transmit_bits(abtUnlock1, 7)
            {
                magicCardType = MifareMagicCardType.GEN_1B;

                // then send unlock2 => Gen1A
                if (_device.InitiatorTransceiveBytes(abtUnlock2, 1, _rxBuffer, (uint)_rxBuffer.Length, 0) > 0 && _rxBuffer[0] == (byte)MifareResponseType.ACK) // transmit_bytes(abtUnlock2, 1)
                {
                    magicCardType = MifareMagicCardType.GEN_1A;
                }
            }

            // reset reader
            // Configure the CRC
            if (!_device.DeviceSetPropertyBool(NfcProperty.HandleCrc, true))
            {
                _device.Perror("nfc_device_set_property_bool");
                return false;
            }

            // Switch off raw send/receive methods
            if (!_device.DeviceSetPropertyBool(NfcProperty.EasyFraming, true))
            {
                _device.Perror("nfc_device_set_property_bool");
                return false;
            }

            return magicCardType != MifareMagicCardType.NONE;
        }

        public bool Authenticate(byte sector, MifareKeyType keyType, byte[] key)
        {
            if (key == null || key.Length != KEY_SIZE || sector >= SECTOR_COUNT)
                return false;

            byte[] abtCmd = new byte[12];
            abtCmd[0] = (byte)(keyType == MifareKeyType.KEY_A ? MifareCommandType.AUTH_A : MifareCommandType.AUTH_B);
            abtCmd[1] = (byte)(sector * BLOCKS_PER_SECTOR);
            Array.Copy(key, 0, abtCmd, 2, KEY_SIZE);
            Array.Copy(Uid, 0, abtCmd, 8, UID_SIZE);

            int result;
            if ((result = _device.InitiatorTransceiveBytes(abtCmd, (uint)abtCmd.Length, _rxBuffer, (uint)_rxBuffer.Length, 0)) < 0)
            {
                if (result == (int)NfcError.NFC_ERFTRANS)
                {
                    // "Invalid received frame", usual means we are
                    // authenticated on a sector but the requested MIFARE cmd (read, write)
                    // is not permitted by current acces bytes;
                    // So there is nothing to do here.
                }
                else
                {
                    _device.Perror("nfc_initiator_transceive_bytes");
                }
                // if auth failed mifare card needs to be reselected
                SelectCard();

                return false;
            }

            return true;
        }

        public bool ReadBlock(byte block, out byte[] blockData)
        {
            blockData = new byte[BLOCK_SIZE];

            if (block >= BLOCKS_TOTAL_COUNT)
                return false;

            byte[] abtCmd = new byte[2];
            abtCmd[0] = (byte)MifareCommandType.READ;
            abtCmd[1] = block;

            int result;
            if ((result = _device.InitiatorTransceiveBytes(abtCmd, (uint)abtCmd.Length, _rxBuffer, (uint)_rxBuffer.Length, 0)) < 0)
            {
                if (result == (int)NfcError.NFC_ERFTRANS)
                {
                    // "Invalid received frame", usual means we are
                    // authenticated on a sector but the requested MIFARE cmd (read, write)
                    // is not permitted by current acces bytes;
                    // So there is nothing to do here.
                }
                else
                {
                    _device.Perror("nfc_initiator_transceive_bytes");
                }
                SelectCard();

                return false;
            }

            if (result == BLOCK_SIZE)
            {
                Array.Copy(_rxBuffer, 0, blockData, 0, blockData.Length);
            }
            else
            {
                SelectCard();

                return false;
            }

            return true;
        }

        public bool WriteBlock(byte block, byte[] blockData)
        {
            if (blockData == null || blockData.Length != BLOCK_SIZE || block >= BLOCKS_TOTAL_COUNT)
                return false;

            byte[] abtCmd = new byte[18];
            abtCmd[0] = (byte)MifareCommandType.WRITE;
            abtCmd[1] = block;
            Array.Copy(blockData, 0, abtCmd, 2, BLOCK_SIZE);

            int result;
            if ((result = _device.InitiatorTransceiveBytes(abtCmd, (uint)abtCmd.Length, _rxBuffer, (uint)_rxBuffer.Length, 0)) < 0)
            {
                if (result == (int)NfcError.NFC_ERFTRANS)
                {
                    // "Invalid received frame", usual means we are
                    // authenticated on a sector but the requested MIFARE cmd (read, write)
                    // is not permitted by current acces bytes;
                    // So there is nothing to do here.
                }
                else
                {
                    _device.Perror("nfc_initiator_transceive_bytes");
                }
                SelectCard();

                return false;
            }

            return true;
        }

        private bool IsMagicGen2()
        {
            var gen2Ats = new byte[9] { 0x09, 0x78, 0x00, 0x91, 0x02, 0xDA, 0xBC, 0x19, 0x10 };

            if (_target.TargetInfo.Iso14443aInfo.szAtsLen > 0 && _target.TargetInfo.Iso14443aInfo.abtAts.Take(gen2Ats.Length).SequenceEqual(gen2Ats))
            {
                return true;
            }
            else
            {
                if (Authenticate(0, MifareKeyType.KEY_A, FACTORY_KEY) ||
                    Authenticate(0, MifareKeyType.KEY_A, _keyAProviderCallback?.Invoke(0, Uid)))
                {
                    if (ReadBlock(0, out byte[] blockData))
                    {
                        if (WriteBlock(0, blockData))
                        {
                            // abort to ensure nothing is written to block 0
                            // AbortCommand runs after already written :(
                            //_device.AbortCommand();

                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static bool IsFirstBlock(int block) =>
            block % 4 == 0;

        public static bool IsTrailerBlock(uint block) =>
            (block + 1) % 4 == 0;

        public static int GetTrailerBlock(int block) =>
            4 * ((block / 4) + 1) - 1;
    }
}