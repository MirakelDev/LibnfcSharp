using System.ComponentModel;

namespace LibnfcSharp.Mifare.Enums
{
    public enum MifareMagicCardType
    {
        [Description("Gen1 UID LOCKED")]
        NONE,

        [Description("Gen1A UID Changeable (Backdoor)")]
        GEN_1A,

        [Description("Gen1B UID Changeable (Backdoor)")]
        GEN_1B,

        [Description("Gen2 CUID")]
        GEN_2
    }
}
