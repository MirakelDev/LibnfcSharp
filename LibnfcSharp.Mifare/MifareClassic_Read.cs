using LibnfcSharp.Mifare.Enums;
using LibnfcSharp.Mifare.Models;
using LibnfcSharp.PInvoke;
using System;

namespace LibnfcSharp.Mifare
{
    public partial class MifareClassic
    {
        public bool ReadManufacturerInfo(out ManufacturerInfo manufacturerInfo)
        {
            var result = ReadManufacturerBlock(out byte[] manufacturerBlock);
            manufacturerInfo = new ManufacturerInfo(manufacturerBlock);
            return result;
        }

        public bool ReadManufacturerBlock(out byte[] manufacturerBlockData)
        {
            manufacturerBlockData = new byte[16];

            if (MagicCardType == MifareMagicCardType.GEN_1 ||
                MagicCardType == MifareMagicCardType.GEN_2)
            {
                if (!Authenticate(0, MifareKeyType.KEY_A, FACTORY_KEY) &&
                    !Authenticate(0, MifareKeyType.KEY_A, _keyAProviderCallback?.Invoke(0, Uid)))
                {
                    return false;
                }

            }

            return ReadBlock(0, out manufacturerBlockData);
        }

        public bool ReadAccessConditions(byte sector, out byte[] accessConditions, bool skipAuthentication = false)
        {
            accessConditions = new byte[ACS_SIZE];

            var trailerBlock = GetTrailerBlock((byte)(sector * BLOCKS_PER_SECTOR));

            if (MagicCardType == MifareMagicCardType.GEN_1 ||
                MagicCardType == MifareMagicCardType.GEN_2)
            {
                if (!skipAuthentication &&
                    !Authenticate(sector, MifareKeyType.KEY_A, FACTORY_KEY) &&
                    !Authenticate(sector, MifareKeyType.KEY_A, _keyAProviderCallback?.Invoke(0, Uid)))
                {
                    return false;
                }

            }

            if (ReadBlock(trailerBlock, out byte[] blockData))
            {
                Array.Copy(blockData, ACS_OFFSET, accessConditions, 0, accessConditions.Length);

                return true;
            }
            return false;
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
                    Perror("nfc_initiator_transceive_bytes");
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
    }
}