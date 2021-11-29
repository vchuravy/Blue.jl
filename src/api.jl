module API

using CEnum

using BlueZ_jll


struct bdaddr_t
    b::NTuple{6, UInt8}
end

function ntoh64(n)
    ccall((:ntoh64, libbluetooth), UInt64, (UInt64,), n)
end

struct uint128_t
    data::NTuple{16, UInt8}
end

function ntoh128(src, dst)
    ccall((:ntoh128, libbluetooth), Cvoid, (Ptr{uint128_t}, Ptr{uint128_t}), src, dst)
end

function btoh128(src, dst)
    ccall((:btoh128, libbluetooth), Cvoid, (Ptr{uint128_t}, Ptr{uint128_t}), src, dst)
end

struct bt_security
    level::UInt8
    key_size::UInt8
end

struct bt_power
    force_active::UInt8
end

struct bt_voice
    setting::UInt16
end

@cenum __JL_Ctag_21::UInt32 begin
    BT_CONNECTED = 1
    BT_OPEN = 2
    BT_BOUND = 3
    BT_LISTEN = 4
    BT_CONNECT = 5
    BT_CONNECT2 = 6
    BT_CONFIG = 7
    BT_DISCONN = 8
    BT_CLOSED = 9
end

function bt_get_le64(ptr)
    ccall((:bt_get_le64, libbluetooth), UInt64, (Ptr{Cvoid},), ptr)
end

function bt_get_be64(ptr)
    ccall((:bt_get_be64, libbluetooth), UInt64, (Ptr{Cvoid},), ptr)
end

function bt_get_le32(ptr)
    ccall((:bt_get_le32, libbluetooth), UInt32, (Ptr{Cvoid},), ptr)
end

function bt_get_be32(ptr)
    ccall((:bt_get_be32, libbluetooth), UInt32, (Ptr{Cvoid},), ptr)
end

function bt_get_le16(ptr)
    ccall((:bt_get_le16, libbluetooth), UInt16, (Ptr{Cvoid},), ptr)
end

function bt_get_be16(ptr)
    ccall((:bt_get_be16, libbluetooth), UInt16, (Ptr{Cvoid},), ptr)
end

function bt_put_le64(val, ptr)
    ccall((:bt_put_le64, libbluetooth), Cvoid, (UInt64, Ptr{Cvoid}), val, ptr)
end

function bt_put_be64(val, ptr)
    ccall((:bt_put_be64, libbluetooth), Cvoid, (UInt64, Ptr{Cvoid}), val, ptr)
end

function bt_put_le32(val, ptr)
    ccall((:bt_put_le32, libbluetooth), Cvoid, (UInt32, Ptr{Cvoid}), val, ptr)
end

function bt_put_be32(val, ptr)
    ccall((:bt_put_be32, libbluetooth), Cvoid, (UInt32, Ptr{Cvoid}), val, ptr)
end

function bt_put_le16(val, ptr)
    ccall((:bt_put_le16, libbluetooth), Cvoid, (UInt16, Ptr{Cvoid}), val, ptr)
end

function bt_put_be16(val, ptr)
    ccall((:bt_put_be16, libbluetooth), Cvoid, (UInt16, Ptr{Cvoid}), val, ptr)
end

function bacmp(ba1, ba2)
    ccall((:bacmp, libbluetooth), Cint, (Ptr{bdaddr_t}, Ptr{bdaddr_t}), ba1, ba2)
end

function bacpy(dst, src)
    ccall((:bacpy, libbluetooth), Cvoid, (Ptr{bdaddr_t}, Ptr{bdaddr_t}), dst, src)
end

function baswap(dst, src)
    ccall((:baswap, libbluetooth), Cvoid, (Ptr{bdaddr_t}, Ptr{bdaddr_t}), dst, src)
end

function strtoba(str)
    ccall((:strtoba, libbluetooth), Ptr{bdaddr_t}, (Ptr{Cchar},), str)
end

function batostr(ba)
    ccall((:batostr, libbluetooth), Ptr{Cchar}, (Ptr{bdaddr_t},), ba)
end

function ba2str(ba, str)
    ccall((:ba2str, libbluetooth), Cint, (Ptr{bdaddr_t}, Ptr{Cchar}), ba, str)
end

function ba2strlc(ba, str)
    ccall((:ba2strlc, libbluetooth), Cint, (Ptr{bdaddr_t}, Ptr{Cchar}), ba, str)
end

function str2ba(str, ba)
    ccall((:str2ba, libbluetooth), Cint, (Ptr{Cchar}, Ptr{bdaddr_t}), str, ba)
end

function ba2oui(ba, oui)
    ccall((:ba2oui, libbluetooth), Cint, (Ptr{bdaddr_t}, Ptr{Cchar}), ba, oui)
end

function bachk(str)
    ccall((:bachk, libbluetooth), Cint, (Ptr{Cchar},), str)
end

function bt_malloc(size)
    ccall((:bt_malloc, libbluetooth), Ptr{Cvoid}, (Csize_t,), size)
end

function bt_free(ptr)
    ccall((:bt_free, libbluetooth), Cvoid, (Ptr{Cvoid},), ptr)
end

function bt_error(code)
    ccall((:bt_error, libbluetooth), Cint, (UInt16,), code)
end

function bt_compidtostr(id)
    ccall((:bt_compidtostr, libbluetooth), Ptr{Cchar}, (Cint,), id)
end

function bswap_128(src, dst)
    ccall((:bswap_128, libbluetooth), Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}), src, dst)
end

const BTPROTO_L2CAP = 0

const BTPROTO_HCI = 1

const BTPROTO_SCO = 2

const BTPROTO_RFCOMM = 3

const BTPROTO_BNEP = 4

const BTPROTO_CMTP = 5

const BTPROTO_HIDP = 6

const BTPROTO_AVDTP = 7

const SOL_HCI = 0

const SOL_L2CAP = 6

const SOL_SCO = 17

const SOL_RFCOMM = 18

const SOL_BLUETOOTH = 274

const BT_SECURITY = 4

const BT_SECURITY_SDP = 0

const BT_SECURITY_LOW = 1

const BT_SECURITY_MEDIUM = 2

const BT_SECURITY_HIGH = 3

const BT_SECURITY_FIPS = 4

const BT_DEFER_SETUP = 7

const BT_FLUSHABLE = 8

const BT_FLUSHABLE_OFF = 0

const BT_FLUSHABLE_ON = 1

const BT_POWER = 9

const BT_POWER_FORCE_ACTIVE_OFF = 0

const BT_POWER_FORCE_ACTIVE_ON = 1

const BT_CHANNEL_POLICY = 10

const BT_CHANNEL_POLICY_BREDR_ONLY = 0

const BT_CHANNEL_POLICY_BREDR_PREFERRED = 1

const BT_CHANNEL_POLICY_AMP_PREFERRED = 2

const BT_VOICE = 11

const BT_SNDMTU = 12

const BT_RCVMTU = 13

const BT_VOICE_TRANSPARENT = 0x0003

const BT_VOICE_CVSD_16BIT = 0x0060

const BT_PHY = 14

const BT_PHY_BR_1M_1SLOT = 0x00000001

const BT_PHY_BR_1M_3SLOT = 0x00000002

const BT_PHY_BR_1M_5SLOT = 0x00000004

const BT_PHY_EDR_2M_1SLOT = 0x00000008

const BT_PHY_EDR_2M_3SLOT = 0x00000010

const BT_PHY_EDR_2M_5SLOT = 0x00000020

const BT_PHY_EDR_3M_1SLOT = 0x00000040

const BT_PHY_EDR_3M_3SLOT = 0x00000080

const BT_PHY_EDR_3M_5SLOT = 0x00000100

const BT_PHY_LE_1M_TX = 0x00000200

const BT_PHY_LE_1M_RX = 0x00000400

const BT_PHY_LE_2M_TX = 0x00000800

const BT_PHY_LE_2M_RX = 0x00001000

const BT_PHY_LE_CODED_TX = 0x00002000

const BT_PHY_LE_CODED_RX = 0x00004000

const BDADDR_BREDR = 0x00

const BDADDR_LE_PUBLIC = 0x01

const BDADDR_LE_RANDOM = 0x02

end # module
