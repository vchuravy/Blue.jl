module API

using CEnum

using BlueZ_jll


const sa_family_t = Cushort

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

@cenum __JL_Ctag_44::UInt32 begin
    HCI_UP = 0
    HCI_INIT = 1
    HCI_RUNNING = 2
    HCI_PSCAN = 3
    HCI_ISCAN = 4
    HCI_AUTH = 5
    HCI_ENCRYPT = 6
    HCI_INQUIRY = 7
    HCI_RAW = 8
end

@cenum __JL_Ctag_45::UInt32 begin
    LE_PUBLIC_ADDRESS = 0
    LE_RANDOM_ADDRESS = 1
end

struct inquiry_cp
    lap::NTuple{3, UInt8}
    length::UInt8
    num_rsp::UInt8
end

struct status_bdaddr_rp
    status::UInt8
    bdaddr::bdaddr_t
end

struct periodic_inquiry_cp
    max_period::UInt16
    min_period::UInt16
    lap::NTuple{3, UInt8}
    length::UInt8
    num_rsp::UInt8
end

struct create_conn_cp
    bdaddr::bdaddr_t
    pkt_type::UInt16
    pscan_rep_mode::UInt8
    pscan_mode::UInt8
    clock_offset::UInt16
    role_switch::UInt8
end

struct disconnect_cp
    handle::UInt16
    reason::UInt8
end

struct add_sco_cp
    handle::UInt16
    pkt_type::UInt16
end

struct create_conn_cancel_cp
    bdaddr::bdaddr_t
end

struct accept_conn_req_cp
    bdaddr::bdaddr_t
    role::UInt8
end

struct reject_conn_req_cp
    bdaddr::bdaddr_t
    reason::UInt8
end

struct link_key_reply_cp
    bdaddr::bdaddr_t
    link_key::NTuple{16, UInt8}
end

struct pin_code_reply_cp
    bdaddr::bdaddr_t
    pin_len::UInt8
    pin_code::NTuple{16, UInt8}
end

struct set_conn_ptype_cp
    handle::UInt16
    pkt_type::UInt16
end

struct auth_requested_cp
    handle::UInt16
end

struct set_conn_encrypt_cp
    handle::UInt16
    encrypt::UInt8
end

struct change_conn_link_key_cp
    handle::UInt16
end

struct master_link_key_cp
    key_flag::UInt8
end

struct remote_name_req_cp
    bdaddr::bdaddr_t
    pscan_rep_mode::UInt8
    pscan_mode::UInt8
    clock_offset::UInt16
end

struct remote_name_req_cancel_cp
    bdaddr::bdaddr_t
end

struct read_remote_features_cp
    handle::UInt16
end

struct read_remote_ext_features_cp
    handle::UInt16
    page_num::UInt8
end

struct read_remote_version_cp
    handle::UInt16
end

struct read_clock_offset_cp
    handle::UInt16
end

struct setup_sync_conn_cp
    handle::UInt16
    tx_bandwith::UInt32
    rx_bandwith::UInt32
    max_latency::UInt16
    voice_setting::UInt16
    retrans_effort::UInt8
    pkt_type::UInt16
end

struct accept_sync_conn_req_cp
    bdaddr::bdaddr_t
    tx_bandwith::UInt32
    rx_bandwith::UInt32
    max_latency::UInt16
    voice_setting::UInt16
    retrans_effort::UInt8
    pkt_type::UInt16
end

struct reject_sync_conn_req_cp
    bdaddr::bdaddr_t
    reason::UInt8
end

struct io_capability_reply_cp
    bdaddr::bdaddr_t
    capability::UInt8
    oob_data::UInt8
    authentication::UInt8
end

struct user_confirm_reply_cp
    bdaddr::bdaddr_t
end

struct user_passkey_reply_cp
    bdaddr::bdaddr_t
    passkey::UInt32
end

struct remote_oob_data_reply_cp
    bdaddr::bdaddr_t
    hash::NTuple{16, UInt8}
    randomizer::NTuple{16, UInt8}
end

struct io_capability_neg_reply_cp
    bdaddr::bdaddr_t
    reason::UInt8
end

struct create_physical_link_cp
    handle::UInt8
    key_length::UInt8
    key_type::UInt8
    key::NTuple{32, UInt8}
end

struct accept_physical_link_cp
    handle::UInt8
    key_length::UInt8
    key_type::UInt8
    key::NTuple{32, UInt8}
end

struct disconnect_physical_link_cp
    handle::UInt8
    reason::UInt8
end

struct create_logical_link_cp
    handle::UInt8
    tx_flow::NTuple{16, UInt8}
    rx_flow::NTuple{16, UInt8}
end

struct disconnect_logical_link_cp
    handle::UInt16
end

struct cancel_logical_link_cp
    handle::UInt8
    tx_flow_id::UInt8
end

struct cancel_logical_link_rp
    status::UInt8
    handle::UInt8
    tx_flow_id::UInt8
end

struct hold_mode_cp
    handle::UInt16
    max_interval::UInt16
    min_interval::UInt16
end

struct sniff_mode_cp
    handle::UInt16
    max_interval::UInt16
    min_interval::UInt16
    attempt::UInt16
    timeout::UInt16
end

struct exit_sniff_mode_cp
    handle::UInt16
end

struct park_mode_cp
    handle::UInt16
    max_interval::UInt16
    min_interval::UInt16
end

struct exit_park_mode_cp
    handle::UInt16
end

struct hci_qos
    service_type::UInt8
    token_rate::UInt32
    peak_bandwidth::UInt32
    latency::UInt32
    delay_variation::UInt32
end

struct qos_setup_cp
    handle::UInt16
    flags::UInt8
    qos::hci_qos
end

struct role_discovery_cp
    handle::UInt16
end

struct role_discovery_rp
    status::UInt8
    handle::UInt16
    role::UInt8
end

struct switch_role_cp
    bdaddr::bdaddr_t
    role::UInt8
end

struct read_link_policy_cp
    handle::UInt16
end

struct read_link_policy_rp
    status::UInt8
    handle::UInt16
    policy::UInt16
end

struct write_link_policy_cp
    handle::UInt16
    policy::UInt16
end

struct write_link_policy_rp
    status::UInt8
    handle::UInt16
end

struct sniff_subrating_cp
    handle::UInt16
    max_latency::UInt16
    min_remote_timeout::UInt16
    min_local_timeout::UInt16
end

struct set_event_mask_cp
    mask::NTuple{8, UInt8}
end

struct set_event_flt_cp
    flt_type::UInt8
    cond_type::UInt8
    condition::NTuple{0, UInt8}
end

struct read_pin_type_rp
    status::UInt8
    pin_type::UInt8
end

struct write_pin_type_cp
    pin_type::UInt8
end

struct read_stored_link_key_cp
    bdaddr::bdaddr_t
    read_all::UInt8
end

struct read_stored_link_key_rp
    status::UInt8
    max_keys::UInt16
    num_keys::UInt16
end

struct write_stored_link_key_cp
    num_keys::UInt8
end

struct write_stored_link_key_rp
    status::UInt8
    num_keys::UInt8
end

struct delete_stored_link_key_cp
    bdaddr::bdaddr_t
    delete_all::UInt8
end

struct delete_stored_link_key_rp
    status::UInt8
    num_keys::UInt16
end

struct change_local_name_cp
    name::NTuple{248, UInt8}
end

struct read_local_name_rp
    status::UInt8
    name::NTuple{248, UInt8}
end

struct read_conn_accept_timeout_rp
    status::UInt8
    timeout::UInt16
end

struct write_conn_accept_timeout_cp
    timeout::UInt16
end

struct read_page_timeout_rp
    status::UInt8
    timeout::UInt16
end

struct write_page_timeout_cp
    timeout::UInt16
end

struct read_scan_enable_rp
    status::UInt8
    enable::UInt8
end

struct read_page_activity_rp
    status::UInt8
    interval::UInt16
    window::UInt16
end

struct write_page_activity_cp
    interval::UInt16
    window::UInt16
end

struct read_inq_activity_rp
    status::UInt8
    interval::UInt16
    window::UInt16
end

struct write_inq_activity_cp
    interval::UInt16
    window::UInt16
end

struct read_class_of_dev_rp
    status::UInt8
    dev_class::NTuple{3, UInt8}
end

struct write_class_of_dev_cp
    dev_class::NTuple{3, UInt8}
end

struct read_voice_setting_rp
    status::UInt8
    voice_setting::UInt16
end

struct write_voice_setting_cp
    voice_setting::UInt16
end

struct read_transmit_power_level_cp
    handle::UInt16
    type::UInt8
end

struct read_transmit_power_level_rp
    status::UInt8
    handle::UInt16
    level::Int8
end

struct host_buffer_size_cp
    acl_mtu::UInt16
    sco_mtu::UInt8
    acl_max_pkt::UInt16
    sco_max_pkt::UInt16
end

struct host_num_comp_pkts_cp
    num_hndl::UInt8
end

struct read_link_supervision_timeout_rp
    status::UInt8
    handle::UInt16
    timeout::UInt16
end

struct write_link_supervision_timeout_cp
    handle::UInt16
    timeout::UInt16
end

struct write_link_supervision_timeout_rp
    status::UInt8
    handle::UInt16
end

struct read_current_iac_lap_rp
    status::UInt8
    num_current_iac::UInt8
    lap::NTuple{64, NTuple{3, UInt8}}
end

struct write_current_iac_lap_cp
    num_current_iac::UInt8
    lap::NTuple{64, NTuple{3, UInt8}}
end

struct set_afh_classification_cp
    map::NTuple{10, UInt8}
end

struct set_afh_classification_rp
    status::UInt8
end

struct read_inquiry_scan_type_rp
    status::UInt8
    type::UInt8
end

struct write_inquiry_scan_type_cp
    type::UInt8
end

struct write_inquiry_scan_type_rp
    status::UInt8
end

struct read_inquiry_mode_rp
    status::UInt8
    mode::UInt8
end

struct write_inquiry_mode_cp
    mode::UInt8
end

struct write_inquiry_mode_rp
    status::UInt8
end

struct read_afh_mode_rp
    status::UInt8
    mode::UInt8
end

struct write_afh_mode_cp
    mode::UInt8
end

struct write_afh_mode_rp
    status::UInt8
end

struct read_ext_inquiry_response_rp
    status::UInt8
    fec::UInt8
    data::NTuple{240, UInt8}
end

struct write_ext_inquiry_response_cp
    fec::UInt8
    data::NTuple{240, UInt8}
end

struct write_ext_inquiry_response_rp
    status::UInt8
end

struct refresh_encryption_key_cp
    handle::UInt16
end

struct refresh_encryption_key_rp
    status::UInt8
end

struct read_simple_pairing_mode_rp
    status::UInt8
    mode::UInt8
end

struct write_simple_pairing_mode_cp
    mode::UInt8
end

struct write_simple_pairing_mode_rp
    status::UInt8
end

struct read_local_oob_data_rp
    status::UInt8
    hash::NTuple{16, UInt8}
    randomizer::NTuple{16, UInt8}
end

struct read_inq_response_tx_power_level_rp
    status::UInt8
    level::Int8
end

struct read_inquiry_transmit_power_level_rp
    status::UInt8
    level::Int8
end

struct write_inquiry_transmit_power_level_cp
    level::Int8
end

struct write_inquiry_transmit_power_level_rp
    status::UInt8
end

struct read_default_error_data_reporting_rp
    status::UInt8
    reporting::UInt8
end

struct write_default_error_data_reporting_cp
    reporting::UInt8
end

struct write_default_error_data_reporting_rp
    status::UInt8
end

struct enhanced_flush_cp
    handle::UInt16
    type::UInt8
end

struct send_keypress_notify_cp
    bdaddr::bdaddr_t
    type::UInt8
end

struct send_keypress_notify_rp
    status::UInt8
end

struct read_log_link_accept_timeout_rp
    status::UInt8
    timeout::UInt16
end

struct write_log_link_accept_timeout_cp
    timeout::UInt16
end

struct read_enhanced_transmit_power_level_rp
    status::UInt8
    handle::UInt16
    level_gfsk::Int8
    level_dqpsk::Int8
    level_8dpsk::Int8
end

struct read_best_effort_flush_timeout_rp
    status::UInt8
    timeout::UInt32
end

struct write_best_effort_flush_timeout_cp
    handle::UInt16
    timeout::UInt32
end

struct write_best_effort_flush_timeout_rp
    status::UInt8
end

struct read_le_host_supported_rp
    status::UInt8
    le::UInt8
    simul::UInt8
end

struct write_le_host_supported_cp
    le::UInt8
    simul::UInt8
end

struct read_local_version_rp
    status::UInt8
    hci_ver::UInt8
    hci_rev::UInt16
    lmp_ver::UInt8
    manufacturer::UInt16
    lmp_subver::UInt16
end

struct read_local_commands_rp
    status::UInt8
    commands::NTuple{64, UInt8}
end

struct read_local_features_rp
    status::UInt8
    features::NTuple{8, UInt8}
end

struct read_local_ext_features_cp
    page_num::UInt8
end

struct read_local_ext_features_rp
    status::UInt8
    page_num::UInt8
    max_page_num::UInt8
    features::NTuple{8, UInt8}
end

struct read_buffer_size_rp
    status::UInt8
    acl_mtu::UInt16
    sco_mtu::UInt8
    acl_max_pkt::UInt16
    sco_max_pkt::UInt16
end

struct read_bd_addr_rp
    status::UInt8
    bdaddr::bdaddr_t
end

struct read_data_block_size_rp
    status::UInt8
    max_acl_len::UInt16
    data_block_len::UInt16
    num_blocks::UInt16
end

struct read_failed_contact_counter_rp
    status::UInt8
    handle::UInt16
    counter::UInt8
end

struct reset_failed_contact_counter_rp
    status::UInt8
    handle::UInt16
end

struct read_link_quality_rp
    status::UInt8
    handle::UInt16
    link_quality::UInt8
end

struct read_rssi_rp
    status::UInt8
    handle::UInt16
    rssi::Int8
end

struct read_afh_map_rp
    status::UInt8
    handle::UInt16
    mode::UInt8
    map::NTuple{10, UInt8}
end

struct read_clock_cp
    handle::UInt16
    which_clock::UInt8
end

struct read_clock_rp
    status::UInt8
    handle::UInt16
    clock::UInt32
    accuracy::UInt16
end

struct read_local_amp_info_rp
    status::UInt8
    amp_status::UInt8
    total_bandwidth::UInt32
    max_guaranteed_bandwidth::UInt32
    min_latency::UInt32
    max_pdu_size::UInt32
    controller_type::UInt8
    pal_caps::UInt16
    max_amp_assoc_length::UInt16
    max_flush_timeout::UInt32
    best_effort_flush_timeout::UInt32
end

struct read_local_amp_assoc_cp
    handle::UInt8
    length_so_far::UInt16
    assoc_length::UInt16
end

struct read_local_amp_assoc_rp
    status::UInt8
    handle::UInt8
    length::UInt16
    fragment::NTuple{248, UInt8}
end

struct write_remote_amp_assoc_cp
    handle::UInt8
    length_so_far::UInt16
    remaining_length::UInt16
    fragment::NTuple{248, UInt8}
end

struct write_remote_amp_assoc_rp
    status::UInt8
    handle::UInt8
end

struct write_simple_pairing_debug_mode_cp
    mode::UInt8
end

struct write_simple_pairing_debug_mode_rp
    status::UInt8
end

struct le_set_event_mask_cp
    mask::NTuple{8, UInt8}
end

struct le_read_buffer_size_rp
    status::UInt8
    pkt_len::UInt16
    max_pkt::UInt8
end

struct le_read_local_supported_features_rp
    status::UInt8
    features::NTuple{8, UInt8}
end

struct le_set_random_address_cp
    bdaddr::bdaddr_t
end

struct le_set_advertising_parameters_cp
    min_interval::UInt16
    max_interval::UInt16
    advtype::UInt8
    own_bdaddr_type::UInt8
    direct_bdaddr_type::UInt8
    direct_bdaddr::bdaddr_t
    chan_map::UInt8
    filter::UInt8
end

struct le_read_advertising_channel_tx_power_rp
    status::UInt8
    level::Int8
end

struct le_set_advertising_data_cp
    length::UInt8
    data::NTuple{31, UInt8}
end

struct le_set_scan_response_data_cp
    length::UInt8
    data::NTuple{31, UInt8}
end

struct le_set_advertise_enable_cp
    enable::UInt8
end

struct le_set_scan_parameters_cp
    type::UInt8
    interval::UInt16
    window::UInt16
    own_bdaddr_type::UInt8
    filter::UInt8
end

struct le_set_scan_enable_cp
    enable::UInt8
    filter_dup::UInt8
end

struct le_create_connection_cp
    interval::UInt16
    window::UInt16
    initiator_filter::UInt8
    peer_bdaddr_type::UInt8
    peer_bdaddr::bdaddr_t
    own_bdaddr_type::UInt8
    min_interval::UInt16
    max_interval::UInt16
    latency::UInt16
    supervision_timeout::UInt16
    min_ce_length::UInt16
    max_ce_length::UInt16
end

struct le_read_white_list_size_rp
    status::UInt8
    size::UInt8
end

struct le_add_device_to_white_list_cp
    bdaddr_type::UInt8
    bdaddr::bdaddr_t
end

struct le_remove_device_from_white_list_cp
    bdaddr_type::UInt8
    bdaddr::bdaddr_t
end

struct le_connection_update_cp
    handle::UInt16
    min_interval::UInt16
    max_interval::UInt16
    latency::UInt16
    supervision_timeout::UInt16
    min_ce_length::UInt16
    max_ce_length::UInt16
end

struct le_set_host_channel_classification_cp
    map::NTuple{5, UInt8}
end

struct le_read_channel_map_cp
    handle::UInt16
end

struct le_read_channel_map_rp
    status::UInt8
    handle::UInt16
    map::NTuple{5, UInt8}
end

struct le_read_remote_used_features_cp
    handle::UInt16
end

struct le_encrypt_cp
    key::NTuple{16, UInt8}
    plaintext::NTuple{16, UInt8}
end

struct le_encrypt_rp
    status::UInt8
    data::NTuple{16, UInt8}
end

struct le_rand_rp
    status::UInt8
    random::UInt64
end

struct le_start_encryption_cp
    handle::UInt16
    random::UInt64
    diversifier::UInt16
    key::NTuple{16, UInt8}
end

struct le_ltk_reply_cp
    handle::UInt16
    key::NTuple{16, UInt8}
end

struct le_ltk_reply_rp
    status::UInt8
    handle::UInt16
end

struct le_ltk_neg_reply_cp
    handle::UInt16
end

struct le_ltk_neg_reply_rp
    status::UInt8
    handle::UInt16
end

struct le_read_supported_states_rp
    status::UInt8
    states::UInt64
end

struct le_receiver_test_cp
    frequency::UInt8
end

struct le_transmitter_test_cp
    frequency::UInt8
    length::UInt8
    payload::UInt8
end

struct le_test_end_rp
    status::UInt8
    num_pkts::UInt16
end

struct le_add_device_to_resolv_list_cp
    bdaddr_type::UInt8
    bdaddr::bdaddr_t
    peer_irk::NTuple{16, UInt8}
    local_irk::NTuple{16, UInt8}
end

struct le_remove_device_from_resolv_list_cp
    bdaddr_type::UInt8
    bdaddr::bdaddr_t
end

struct le_read_resolv_list_size_rp
    status::UInt8
    size::UInt8
end

struct le_set_address_resolution_enable_cp
    enable::UInt8
end

struct inquiry_info
    bdaddr::bdaddr_t
    pscan_rep_mode::UInt8
    pscan_period_mode::UInt8
    pscan_mode::UInt8
    dev_class::NTuple{3, UInt8}
    clock_offset::UInt16
end

struct evt_conn_complete
    status::UInt8
    handle::UInt16
    bdaddr::bdaddr_t
    link_type::UInt8
    encr_mode::UInt8
end

struct evt_conn_request
    bdaddr::bdaddr_t
    dev_class::NTuple{3, UInt8}
    link_type::UInt8
end

struct evt_disconn_complete
    status::UInt8
    handle::UInt16
    reason::UInt8
end

struct evt_auth_complete
    status::UInt8
    handle::UInt16
end

struct evt_remote_name_req_complete
    status::UInt8
    bdaddr::bdaddr_t
    name::NTuple{248, UInt8}
end

struct evt_encrypt_change
    status::UInt8
    handle::UInt16
    encrypt::UInt8
end

struct evt_change_conn_link_key_complete
    status::UInt8
    handle::UInt16
end

struct evt_master_link_key_complete
    status::UInt8
    handle::UInt16
    key_flag::UInt8
end

struct evt_read_remote_features_complete
    status::UInt8
    handle::UInt16
    features::NTuple{8, UInt8}
end

struct evt_read_remote_version_complete
    status::UInt8
    handle::UInt16
    lmp_ver::UInt8
    manufacturer::UInt16
    lmp_subver::UInt16
end

struct evt_qos_setup_complete
    status::UInt8
    handle::UInt16
    flags::UInt8
    qos::hci_qos
end

struct evt_cmd_complete
    ncmd::UInt8
    opcode::UInt16
end

struct evt_cmd_status
    status::UInt8
    ncmd::UInt8
    opcode::UInt16
end

struct evt_hardware_error
    code::UInt8
end

struct evt_flush_occured
    handle::UInt16
end

struct evt_role_change
    status::UInt8
    bdaddr::bdaddr_t
    role::UInt8
end

struct evt_num_comp_pkts
    num_hndl::UInt8
end

struct evt_mode_change
    status::UInt8
    handle::UInt16
    mode::UInt8
    interval::UInt16
end

struct evt_return_link_keys
    num_keys::UInt8
end

struct evt_pin_code_req
    bdaddr::bdaddr_t
end

struct evt_link_key_req
    bdaddr::bdaddr_t
end

struct evt_link_key_notify
    bdaddr::bdaddr_t
    link_key::NTuple{16, UInt8}
    key_type::UInt8
end

struct evt_data_buffer_overflow
    link_type::UInt8
end

struct evt_max_slots_change
    handle::UInt16
    max_slots::UInt8
end

struct evt_read_clock_offset_complete
    status::UInt8
    handle::UInt16
    clock_offset::UInt16
end

struct evt_conn_ptype_changed
    status::UInt8
    handle::UInt16
    ptype::UInt16
end

struct evt_qos_violation
    handle::UInt16
end

struct evt_pscan_rep_mode_change
    bdaddr::bdaddr_t
    pscan_rep_mode::UInt8
end

struct evt_flow_spec_complete
    status::UInt8
    handle::UInt16
    flags::UInt8
    direction::UInt8
    qos::hci_qos
end

struct inquiry_info_with_rssi
    bdaddr::bdaddr_t
    pscan_rep_mode::UInt8
    pscan_period_mode::UInt8
    dev_class::NTuple{3, UInt8}
    clock_offset::UInt16
    rssi::Int8
end

struct inquiry_info_with_rssi_and_pscan_mode
    bdaddr::bdaddr_t
    pscan_rep_mode::UInt8
    pscan_period_mode::UInt8
    pscan_mode::UInt8
    dev_class::NTuple{3, UInt8}
    clock_offset::UInt16
    rssi::Int8
end

struct evt_read_remote_ext_features_complete
    status::UInt8
    handle::UInt16
    page_num::UInt8
    max_page_num::UInt8
    features::NTuple{8, UInt8}
end

struct evt_sync_conn_complete
    status::UInt8
    handle::UInt16
    bdaddr::bdaddr_t
    link_type::UInt8
    trans_interval::UInt8
    retrans_window::UInt8
    rx_pkt_len::UInt16
    tx_pkt_len::UInt16
    air_mode::UInt8
end

struct evt_sync_conn_changed
    status::UInt8
    handle::UInt16
    trans_interval::UInt8
    retrans_window::UInt8
    rx_pkt_len::UInt16
    tx_pkt_len::UInt16
end

struct evt_sniff_subrating
    status::UInt8
    handle::UInt16
    max_tx_latency::UInt16
    max_rx_latency::UInt16
    min_remote_timeout::UInt16
    min_local_timeout::UInt16
end

struct extended_inquiry_info
    bdaddr::bdaddr_t
    pscan_rep_mode::UInt8
    pscan_period_mode::UInt8
    dev_class::NTuple{3, UInt8}
    clock_offset::UInt16
    rssi::Int8
    data::NTuple{240, UInt8}
end

struct evt_encryption_key_refresh_complete
    status::UInt8
    handle::UInt16
end

struct evt_io_capability_request
    bdaddr::bdaddr_t
end

struct evt_io_capability_response
    bdaddr::bdaddr_t
    capability::UInt8
    oob_data::UInt8
    authentication::UInt8
end

struct evt_user_confirm_request
    bdaddr::bdaddr_t
    passkey::UInt32
end

struct evt_user_passkey_request
    bdaddr::bdaddr_t
end

struct evt_remote_oob_data_request
    bdaddr::bdaddr_t
end

struct evt_simple_pairing_complete
    status::UInt8
    bdaddr::bdaddr_t
end

struct evt_link_supervision_timeout_changed
    handle::UInt16
    timeout::UInt16
end

struct evt_enhanced_flush_complete
    handle::UInt16
end

struct evt_user_passkey_notify
    bdaddr::bdaddr_t
    passkey::UInt32
end

struct evt_keypress_notify
    bdaddr::bdaddr_t
    type::UInt8
end

struct evt_remote_host_features_notify
    bdaddr::bdaddr_t
    features::NTuple{8, UInt8}
end

struct evt_le_meta_event
    subevent::UInt8
    data::NTuple{0, UInt8}
end

struct evt_le_connection_complete
    status::UInt8
    handle::UInt16
    role::UInt8
    peer_bdaddr_type::UInt8
    peer_bdaddr::bdaddr_t
    interval::UInt16
    latency::UInt16
    supervision_timeout::UInt16
    master_clock_accuracy::UInt8
end

struct le_advertising_info
    evt_type::UInt8
    bdaddr_type::UInt8
    bdaddr::bdaddr_t
    length::UInt8
    data::NTuple{0, UInt8}
end

struct evt_le_connection_update_complete
    status::UInt8
    handle::UInt16
    interval::UInt16
    latency::UInt16
    supervision_timeout::UInt16
end

struct evt_le_read_remote_used_features_complete
    status::UInt8
    handle::UInt16
    features::NTuple{8, UInt8}
end

struct evt_le_long_term_key_request
    handle::UInt16
    random::UInt64
    diversifier::UInt16
end

struct evt_physical_link_complete
    status::UInt8
    handle::UInt8
end

struct evt_disconn_physical_link_complete
    status::UInt8
    handle::UInt8
    reason::UInt8
end

struct evt_physical_link_loss_warning
    handle::UInt8
    reason::UInt8
end

struct evt_physical_link_recovery
    handle::UInt8
end

struct evt_logical_link_complete
    status::UInt8
    log_handle::UInt16
    handle::UInt8
    tx_flow_id::UInt8
end

struct evt_flow_spec_modify_complete
    status::UInt8
    handle::UInt16
end

struct cmplt_handle
    handle::UInt16
    num_cmplt_pkts::UInt16
    num_cmplt_blks::UInt16
end

struct evt_num_completed_blocks
    total_num_blocks::UInt16
    num_handles::UInt8
    handles::NTuple{0, cmplt_handle}
end

struct evt_amp_status_change
    status::UInt8
    amp_status::UInt8
end

struct evt_stack_internal
    type::UInt16
    data::NTuple{0, UInt8}
end

struct evt_si_device
    event::UInt16
    dev_id::UInt16
end

struct hci_command_hdr
    opcode::UInt16
    plen::UInt8
end

struct hci_event_hdr
    evt::UInt8
    plen::UInt8
end

struct hci_acl_hdr
    handle::UInt16
    dlen::UInt16
end

struct hci_sco_hdr
    handle::UInt16
    dlen::UInt8
end

struct hci_msg_hdr
    device::UInt16
    type::UInt16
    plen::UInt16
end

struct sockaddr_hci
    hci_family::sa_family_t
    hci_dev::Cushort
    hci_channel::Cushort
end

struct hci_filter
    type_mask::UInt32
    event_mask::NTuple{2, UInt32}
    opcode::UInt16
end

struct hci_dev_stats
    err_rx::UInt32
    err_tx::UInt32
    cmd_tx::UInt32
    evt_rx::UInt32
    acl_tx::UInt32
    acl_rx::UInt32
    sco_tx::UInt32
    sco_rx::UInt32
    byte_rx::UInt32
    byte_tx::UInt32
end

struct hci_dev_info
    dev_id::UInt16
    name::NTuple{8, Cchar}
    bdaddr::bdaddr_t
    flags::UInt32
    type::UInt8
    features::NTuple{8, UInt8}
    pkt_type::UInt32
    link_policy::UInt32
    link_mode::UInt32
    acl_mtu::UInt16
    acl_pkts::UInt16
    sco_mtu::UInt16
    sco_pkts::UInt16
    stat::hci_dev_stats
end

struct hci_conn_info
    handle::UInt16
    bdaddr::bdaddr_t
    type::UInt8
    out::UInt8
    state::UInt16
    link_mode::UInt32
end

struct hci_dev_req
    dev_id::UInt16
    dev_opt::UInt32
end

struct hci_dev_list_req
    dev_num::UInt16
    dev_req::NTuple{0, hci_dev_req}
end

struct hci_conn_list_req
    dev_id::UInt16
    conn_num::UInt16
    conn_info::NTuple{0, hci_conn_info}
end

struct hci_conn_info_req
    bdaddr::bdaddr_t
    type::UInt8
    conn_info::NTuple{0, hci_conn_info}
end

struct hci_auth_info_req
    bdaddr::bdaddr_t
    type::UInt8
end

struct hci_inquiry_req
    dev_id::UInt16
    flags::UInt16
    lap::NTuple{3, UInt8}
    length::UInt8
    num_rsp::UInt8
end

# typedef void ( * sdp_list_func_t ) ( void * , void * )
const sdp_list_func_t = Ptr{Cvoid}

# typedef void ( * sdp_free_func_t ) ( void * )
const sdp_free_func_t = Ptr{Cvoid}

# typedef int ( * sdp_comp_func_t ) ( const void * , const void * )
const sdp_comp_func_t = Ptr{Cvoid}

function sdp_list_append()
    ccall((:sdp_list_append, libbluetooth), Ptr{Cint}, ())
end

function sdp_list_remove()
    ccall((:sdp_list_remove, libbluetooth), Ptr{Cint}, ())
end

function sdp_list_insert_sorted()
    ccall((:sdp_list_insert_sorted, libbluetooth), Ptr{Cint}, ())
end

function sdp_list_free(list, f)
    ccall((:sdp_list_free, libbluetooth), Cvoid, (Ptr{Cint}, sdp_free_func_t), list, f)
end

function sdp_list_len(list)
    ccall((:sdp_list_len, libbluetooth), Cint, (Ptr{Cint},), list)
end

function sdp_list_find()
    ccall((:sdp_list_find, libbluetooth), Ptr{Cint}, ())
end

function sdp_list_foreach(list, f, u)
    ccall((:sdp_list_foreach, libbluetooth), Cvoid, (Ptr{Cint}, sdp_list_func_t, Ptr{Cvoid}), list, f, u)
end

struct sdp_session_t
    sock::Cint
    state::Cint
    _local::Cint
    flags::Cint
    tid::UInt16
    priv::Ptr{Cvoid}
end

@cenum sdp_attrreq_type_t::UInt32 begin
    SDP_ATTR_REQ_INDIVIDUAL = 1
    SDP_ATTR_REQ_RANGE = 2
end

# typedef void sdp_callback_t ( uint8_t type , uint16_t status , uint8_t * rsp , size_t size , void * udata )
const sdp_callback_t = Cvoid

function sdp_connect(src, dst, flags)
    ccall((:sdp_connect, libbluetooth), Ptr{sdp_session_t}, (Ptr{bdaddr_t}, Ptr{bdaddr_t}, UInt32), src, dst, flags)
end

function sdp_close(session)
    ccall((:sdp_close, libbluetooth), Cint, (Ptr{sdp_session_t},), session)
end

function sdp_get_socket(session)
    ccall((:sdp_get_socket, libbluetooth), Cint, (Ptr{sdp_session_t},), session)
end

function sdp_create(sk, flags)
    ccall((:sdp_create, libbluetooth), Ptr{sdp_session_t}, (Cint, UInt32), sk, flags)
end

function sdp_get_error(session)
    ccall((:sdp_get_error, libbluetooth), Cint, (Ptr{sdp_session_t},), session)
end

function sdp_process(session)
    ccall((:sdp_process, libbluetooth), Cint, (Ptr{sdp_session_t},), session)
end

function sdp_set_notify(session, func, udata)
    ccall((:sdp_set_notify, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cvoid}, Ptr{Cvoid}), session, func, udata)
end

function sdp_service_search_async(session, search, max_rec_num)
    ccall((:sdp_service_search_async, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}, UInt16), session, search, max_rec_num)
end

function sdp_service_attr_async(session, handle, reqtype, attrid_list)
    ccall((:sdp_service_attr_async, libbluetooth), Cint, (Ptr{sdp_session_t}, UInt32, sdp_attrreq_type_t, Ptr{Cint}), session, handle, reqtype, attrid_list)
end

function sdp_service_search_attr_async(session, search, reqtype, attrid_list)
    ccall((:sdp_service_search_attr_async, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}, sdp_attrreq_type_t, Ptr{Cint}), session, search, reqtype, attrid_list)
end

function sdp_gen_tid(session)
    ccall((:sdp_gen_tid, libbluetooth), UInt16, (Ptr{sdp_session_t},), session)
end

function sdp_general_inquiry(ii, dev_num, duration, found)
    ccall((:sdp_general_inquiry, libbluetooth), Cint, (Ptr{inquiry_info}, Cint, Cint, Ptr{UInt8}), ii, dev_num, duration, found)
end

function sdp_get_int_attr(rec, attr, value)
    ccall((:sdp_get_int_attr, libbluetooth), Cint, (Ptr{Cint}, UInt16, Ptr{Cint}), rec, attr, value)
end

function sdp_get_string_attr(rec, attr, value, valuelen)
    ccall((:sdp_get_string_attr, libbluetooth), Cint, (Ptr{Cint}, UInt16, Ptr{Cchar}, Cint), rec, attr, value, valuelen)
end

function sdp_data_alloc()
    ccall((:sdp_data_alloc, libbluetooth), Ptr{Cint}, ())
end

function sdp_data_alloc_with_length()
    ccall((:sdp_data_alloc_with_length, libbluetooth), Ptr{Cint}, ())
end

function sdp_data_free(data)
    ccall((:sdp_data_free, libbluetooth), Cvoid, (Ptr{Cint},), data)
end

function sdp_data_get()
    ccall((:sdp_data_get, libbluetooth), Ptr{Cint}, ())
end

function sdp_seq_alloc()
    ccall((:sdp_seq_alloc, libbluetooth), Ptr{Cint}, ())
end

function sdp_seq_alloc_with_length()
    ccall((:sdp_seq_alloc_with_length, libbluetooth), Ptr{Cint}, ())
end

function sdp_seq_append()
    ccall((:sdp_seq_append, libbluetooth), Ptr{Cint}, ())
end

function sdp_attr_add(rec, attr, data)
    ccall((:sdp_attr_add, libbluetooth), Cint, (Ptr{Cint}, UInt16, Ptr{Cint}), rec, attr, data)
end

function sdp_attr_remove(rec, attr)
    ccall((:sdp_attr_remove, libbluetooth), Cvoid, (Ptr{Cint}, UInt16), rec, attr)
end

function sdp_attr_replace(rec, attr, data)
    ccall((:sdp_attr_replace, libbluetooth), Cvoid, (Ptr{Cint}, UInt16, Ptr{Cint}), rec, attr, data)
end

function sdp_set_uuidseq_attr(rec, attr, seq)
    ccall((:sdp_set_uuidseq_attr, libbluetooth), Cint, (Ptr{Cint}, UInt16, Ptr{Cint}), rec, attr, seq)
end

function sdp_get_uuidseq_attr(rec, attr, seqp)
    ccall((:sdp_get_uuidseq_attr, libbluetooth), Cint, (Ptr{Cint}, UInt16, Ptr{Ptr{Cint}}), rec, attr, seqp)
end

function sdp_attr_add_new(rec, attr, dtd, p)
    ccall((:sdp_attr_add_new, libbluetooth), Cint, (Ptr{Cint}, UInt16, UInt8, Ptr{Cvoid}), rec, attr, dtd, p)
end

function sdp_set_info_attr(rec, name, prov, desc)
    ccall((:sdp_set_info_attr, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cchar}, Ptr{Cchar}, Ptr{Cchar}), rec, name, prov, desc)
end

function sdp_set_service_classes(rec, seq)
    ccall((:sdp_set_service_classes, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, seq)
end

function sdp_get_service_classes(rec, seqp)
    ccall((:sdp_get_service_classes, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, seqp)
end

function sdp_set_browse_groups(rec, seq)
    ccall((:sdp_set_browse_groups, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, seq)
end

function sdp_set_access_protos(rec, proto)
    ccall((:sdp_set_access_protos, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, proto)
end

function sdp_set_add_access_protos(rec, proto)
    ccall((:sdp_set_add_access_protos, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, proto)
end

function sdp_get_proto_port(list, proto)
    ccall((:sdp_get_proto_port, libbluetooth), Cint, (Ptr{Cint}, Cint), list, proto)
end

function sdp_get_proto_desc()
    ccall((:sdp_get_proto_desc, libbluetooth), Ptr{Cint}, ())
end

function sdp_set_lang_attr(rec, list)
    ccall((:sdp_set_lang_attr, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, list)
end

function sdp_set_service_ttl(rec, ttl)
    ccall((:sdp_set_service_ttl, libbluetooth), Cint, (Ptr{Cint}, UInt32), rec, ttl)
end

function sdp_set_record_state(rec, state)
    ccall((:sdp_set_record_state, libbluetooth), Cint, (Ptr{Cint}, UInt32), rec, state)
end

function sdp_set_service_id(rec, uuid)
    ccall((:sdp_set_service_id, libbluetooth), Cvoid, (Ptr{Cint}, Cint), rec, uuid)
end

function sdp_set_group_id(rec, grouuuid)
    ccall((:sdp_set_group_id, libbluetooth), Cvoid, (Ptr{Cint}, Cint), rec, grouuuid)
end

function sdp_set_service_avail(rec, avail)
    ccall((:sdp_set_service_avail, libbluetooth), Cint, (Ptr{Cint}, UInt8), rec, avail)
end

function sdp_set_profile_descs(rec, desc)
    ccall((:sdp_set_profile_descs, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, desc)
end

function sdp_set_url_attr(rec, clientExecURL, docURL, iconURL)
    ccall((:sdp_set_url_attr, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cchar}, Ptr{Cchar}, Ptr{Cchar}), rec, clientExecURL, docURL, iconURL)
end

function sdp_service_search_req(session, search, max_rec_num, rsp_list)
    ccall((:sdp_service_search_req, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}, UInt16, Ptr{Ptr{Cint}}), session, search, max_rec_num, rsp_list)
end

function sdp_service_attr_req()
    ccall((:sdp_service_attr_req, libbluetooth), Ptr{Cint}, ())
end

function sdp_service_search_attr_req(session, search, reqtype, attrid_list, rsp_list)
    ccall((:sdp_service_search_attr_req, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}, sdp_attrreq_type_t, Ptr{Cint}, Ptr{Ptr{Cint}}), session, search, reqtype, attrid_list, rsp_list)
end

function sdp_record_alloc()
    ccall((:sdp_record_alloc, libbluetooth), Ptr{Cint}, ())
end

function sdp_record_free(rec)
    ccall((:sdp_record_free, libbluetooth), Cvoid, (Ptr{Cint},), rec)
end

function sdp_device_record_register_binary(session, device, data, size, flags, handle)
    ccall((:sdp_device_record_register_binary, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{bdaddr_t}, Ptr{UInt8}, UInt32, UInt8, Ptr{UInt32}), session, device, data, size, flags, handle)
end

function sdp_device_record_register(session, device, rec, flags)
    ccall((:sdp_device_record_register, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{bdaddr_t}, Ptr{Cint}, UInt8), session, device, rec, flags)
end

function sdp_record_register(session, rec, flags)
    ccall((:sdp_record_register, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}, UInt8), session, rec, flags)
end

function sdp_device_record_unregister_binary(session, device, handle)
    ccall((:sdp_device_record_unregister_binary, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{bdaddr_t}, UInt32), session, device, handle)
end

function sdp_device_record_unregister(session, device, rec)
    ccall((:sdp_device_record_unregister, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{bdaddr_t}, Ptr{Cint}), session, device, rec)
end

function sdp_record_unregister(session, rec)
    ccall((:sdp_record_unregister, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}), session, rec)
end

function sdp_device_record_update_binary(session, device, handle, data, size)
    ccall((:sdp_device_record_update_binary, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{bdaddr_t}, UInt32, Ptr{UInt8}, UInt32), session, device, handle, data, size)
end

function sdp_device_record_update(session, device, rec)
    ccall((:sdp_device_record_update, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{bdaddr_t}, Ptr{Cint}), session, device, rec)
end

function sdp_record_update(sess, rec)
    ccall((:sdp_record_update, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{Cint}), sess, rec)
end

function sdp_record_print(rec)
    ccall((:sdp_record_print, libbluetooth), Cvoid, (Ptr{Cint},), rec)
end

function sdp_uuid16_create()
    ccall((:sdp_uuid16_create, libbluetooth), Ptr{Cint}, ())
end

function sdp_uuid32_create()
    ccall((:sdp_uuid32_create, libbluetooth), Ptr{Cint}, ())
end

function sdp_uuid128_create()
    ccall((:sdp_uuid128_create, libbluetooth), Ptr{Cint}, ())
end

function sdp_uuid16_cmp(p1, p2)
    ccall((:sdp_uuid16_cmp, libbluetooth), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), p1, p2)
end

function sdp_uuid128_cmp(p1, p2)
    ccall((:sdp_uuid128_cmp, libbluetooth), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), p1, p2)
end

function sdp_uuid_cmp(p1, p2)
    ccall((:sdp_uuid_cmp, libbluetooth), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), p1, p2)
end

function sdp_uuid_to_uuid128()
    ccall((:sdp_uuid_to_uuid128, libbluetooth), Ptr{Cint}, ())
end

function sdp_uuid16_to_uuid128(uuid128, uuid16)
    ccall((:sdp_uuid16_to_uuid128, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cint}), uuid128, uuid16)
end

function sdp_uuid32_to_uuid128(uuid128, uuid32)
    ccall((:sdp_uuid32_to_uuid128, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cint}), uuid128, uuid32)
end

function sdp_uuid128_to_uuid(uuid)
    ccall((:sdp_uuid128_to_uuid, libbluetooth), Cint, (Ptr{Cint},), uuid)
end

function sdp_uuid_to_proto(uuid)
    ccall((:sdp_uuid_to_proto, libbluetooth), Cint, (Ptr{Cint},), uuid)
end

function sdp_uuid_extract(buffer, bufsize, uuid, scanned)
    ccall((:sdp_uuid_extract, libbluetooth), Cint, (Ptr{UInt8}, Cint, Ptr{Cint}, Ptr{Cint}), buffer, bufsize, uuid, scanned)
end

function sdp_uuid_print(uuid)
    ccall((:sdp_uuid_print, libbluetooth), Cvoid, (Ptr{Cint},), uuid)
end

function sdp_uuid2strn(uuid, str, n)
    ccall((:sdp_uuid2strn, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Csize_t), uuid, str, n)
end

function sdp_proto_uuid2strn(uuid, str, n)
    ccall((:sdp_proto_uuid2strn, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Csize_t), uuid, str, n)
end

function sdp_svclass_uuid2strn(uuid, str, n)
    ccall((:sdp_svclass_uuid2strn, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Csize_t), uuid, str, n)
end

function sdp_profile_uuid2strn(uuid, str, n)
    ccall((:sdp_profile_uuid2strn, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Csize_t), uuid, str, n)
end

function sdp_get_access_protos(rec, protos)
    ccall((:sdp_get_access_protos, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, protos)
end

function sdp_get_add_access_protos(rec, protos)
    ccall((:sdp_get_add_access_protos, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, protos)
end

function sdp_get_browse_groups(rec, seqp)
    ccall((:sdp_get_browse_groups, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, seqp)
end

function sdp_get_lang_attr(rec, langSeq)
    ccall((:sdp_get_lang_attr, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, langSeq)
end

function sdp_get_profile_descs(rec, profDesc)
    ccall((:sdp_get_profile_descs, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, profDesc)
end

function sdp_get_server_ver(rec, pVnumList)
    ccall((:sdp_get_server_ver, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, pVnumList)
end

function sdp_get_service_id(rec, uuid)
    ccall((:sdp_get_service_id, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, uuid)
end

function sdp_get_group_id(rec, uuid)
    ccall((:sdp_get_group_id, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, uuid)
end

function sdp_get_record_state(rec, svcRecState)
    ccall((:sdp_get_record_state, libbluetooth), Cint, (Ptr{Cint}, Ptr{UInt32}), rec, svcRecState)
end

function sdp_get_service_avail(rec, svcAvail)
    ccall((:sdp_get_service_avail, libbluetooth), Cint, (Ptr{Cint}, Ptr{UInt8}), rec, svcAvail)
end

function sdp_get_service_ttl(rec, svcTTLInfo)
    ccall((:sdp_get_service_ttl, libbluetooth), Cint, (Ptr{Cint}, Ptr{UInt32}), rec, svcTTLInfo)
end

function sdp_get_database_state(rec, svcDBState)
    ccall((:sdp_get_database_state, libbluetooth), Cint, (Ptr{Cint}, Ptr{UInt32}), rec, svcDBState)
end

function sdp_get_service_name(rec, str, len)
    ccall((:sdp_get_service_name, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Cint), rec, str, len)
end

function sdp_get_service_desc(rec, str, len)
    ccall((:sdp_get_service_desc, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Cint), rec, str, len)
end

function sdp_get_provider_name(rec, str, len)
    ccall((:sdp_get_provider_name, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Cint), rec, str, len)
end

function sdp_get_doc_url(rec, str, len)
    ccall((:sdp_get_doc_url, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Cint), rec, str, len)
end

function sdp_get_clnt_exec_url(rec, str, len)
    ccall((:sdp_get_clnt_exec_url, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Cint), rec, str, len)
end

function sdp_get_icon_url(rec, str, len)
    ccall((:sdp_get_icon_url, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cchar}, Cint), rec, str, len)
end

function sdp_set_supp_feat(rec, sf)
    ccall((:sdp_set_supp_feat, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, sf)
end

function sdp_get_supp_feat(rec, seqp)
    ccall((:sdp_get_supp_feat, libbluetooth), Cint, (Ptr{Cint}, Ptr{Ptr{Cint}}), rec, seqp)
end

function sdp_extract_pdu()
    ccall((:sdp_extract_pdu, libbluetooth), Ptr{Cint}, ())
end

function sdp_copy_record()
    ccall((:sdp_copy_record, libbluetooth), Ptr{Cint}, ())
end

function sdp_data_print(data)
    ccall((:sdp_data_print, libbluetooth), Cvoid, (Ptr{Cint},), data)
end

function sdp_print_service_attr(alist)
    ccall((:sdp_print_service_attr, libbluetooth), Cvoid, (Ptr{Cint},), alist)
end

function sdp_attrid_comp_func(key1, key2)
    ccall((:sdp_attrid_comp_func, libbluetooth), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), key1, key2)
end

function sdp_set_seq_len(ptr, length)
    ccall((:sdp_set_seq_len, libbluetooth), Cvoid, (Ptr{UInt8}, UInt32), ptr, length)
end

function sdp_set_attrid(pdu, id)
    ccall((:sdp_set_attrid, libbluetooth), Cvoid, (Ptr{Cint}, UInt16), pdu, id)
end

function sdp_append_to_pdu(dst, d)
    ccall((:sdp_append_to_pdu, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cint}), dst, d)
end

function sdp_append_to_buf(dst, data, len)
    ccall((:sdp_append_to_buf, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{UInt8}, UInt32), dst, data, len)
end

function sdp_gen_pdu(pdu, data)
    ccall((:sdp_gen_pdu, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), pdu, data)
end

function sdp_gen_record_pdu(rec, pdu)
    ccall((:sdp_gen_record_pdu, libbluetooth), Cint, (Ptr{Cint}, Ptr{Cint}), rec, pdu)
end

function sdp_extract_seqtype(buf, bufsize, dtdp, size)
    ccall((:sdp_extract_seqtype, libbluetooth), Cint, (Ptr{UInt8}, Cint, Ptr{UInt8}, Ptr{Cint}), buf, bufsize, dtdp, size)
end

function sdp_extract_attr()
    ccall((:sdp_extract_attr, libbluetooth), Ptr{Cint}, ())
end

function sdp_pattern_add_uuid(rec, uuid)
    ccall((:sdp_pattern_add_uuid, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cint}), rec, uuid)
end

function sdp_pattern_add_uuidseq(rec, seq)
    ccall((:sdp_pattern_add_uuidseq, libbluetooth), Cvoid, (Ptr{Cint}, Ptr{Cint}), rec, seq)
end

function sdp_send_req_w4_rsp(session, req, rsp, reqsize, rspsize)
    ccall((:sdp_send_req_w4_rsp, libbluetooth), Cint, (Ptr{sdp_session_t}, Ptr{UInt8}, Ptr{UInt8}, UInt32, Ptr{UInt32}), session, req, rsp, reqsize, rspsize)
end

function sdp_add_lang_attr(rec)
    ccall((:sdp_add_lang_attr, libbluetooth), Cvoid, (Ptr{Cint},), rec)
end

struct hci_request
    ogf::Cint
    ocf::Cint
    event::Cint
    cparam::Ptr{Cvoid}
    clen::Cint
    rparam::Ptr{Cvoid}
    rlen::Cint
end

struct hci_version
    manufacturer::Cint
    hci_ver::Cint
    hci_rev::Cint
    lmp_ver::Cint
    lmp_subver::Cint
end

function hci_open_dev(dev_id)
    ccall((:hci_open_dev, libbluetooth), Cint, (Cint,), dev_id)
end

function hci_close_dev(dd)
    ccall((:hci_close_dev, libbluetooth), Cint, (Cint,), dd)
end

function hci_send_cmd(dd, ogf, ocf, plen, param)
    ccall((:hci_send_cmd, libbluetooth), Cint, (Cint, Cint, Cint, Cint, Ptr{Cvoid}), dd, ogf, ocf, plen, param)
end

function hci_send_req(dd, req, timeout)
    ccall((:hci_send_req, libbluetooth), Cint, (Cint, Ptr{hci_request}, Cint), dd, req, timeout)
end

function hci_create_connection(dd, bdaddr, ptype, clkoffset, rswitch, handle, to)
    ccall((:hci_create_connection, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint, Cint, Ptr{Cint}, Cint), dd, bdaddr, ptype, clkoffset, rswitch, handle, to)
end

function hci_disconnect(dd, handle, reason, to)
    ccall((:hci_disconnect, libbluetooth), Cint, (Cint, Cint, Cint, Cint), dd, handle, reason, to)
end

function hci_inquiry(dev_id, len, num_rsp, lap, ii, flags)
    ccall((:hci_inquiry, libbluetooth), Cint, (Cint, Cint, Cint, Ptr{Cint}, Ptr{Ptr{Cint}}, Clong), dev_id, len, num_rsp, lap, ii, flags)
end

function hci_devinfo(dev_id, di)
    ccall((:hci_devinfo, libbluetooth), Cint, (Cint, Ptr{hci_dev_info}), dev_id, di)
end

function hci_devba(dev_id, bdaddr)
    ccall((:hci_devba, libbluetooth), Cint, (Cint, Ptr{Cint}), dev_id, bdaddr)
end

function hci_devid(str)
    ccall((:hci_devid, libbluetooth), Cint, (Ptr{Cchar},), str)
end

function hci_read_local_name(dd, len, name, to)
    ccall((:hci_read_local_name, libbluetooth), Cint, (Cint, Cint, Ptr{Cchar}, Cint), dd, len, name, to)
end

function hci_write_local_name(dd, name, to)
    ccall((:hci_write_local_name, libbluetooth), Cint, (Cint, Ptr{Cchar}, Cint), dd, name, to)
end

function hci_read_remote_name(dd, bdaddr, len, name, to)
    ccall((:hci_read_remote_name, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Ptr{Cchar}, Cint), dd, bdaddr, len, name, to)
end

function hci_read_remote_name_with_clock_offset(dd, bdaddr, pscan_rep_mode, clkoffset, len, name, to)
    ccall((:hci_read_remote_name_with_clock_offset, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint, Cint, Ptr{Cchar}, Cint), dd, bdaddr, pscan_rep_mode, clkoffset, len, name, to)
end

function hci_read_remote_name_cancel(dd, bdaddr, to)
    ccall((:hci_read_remote_name_cancel, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, bdaddr, to)
end

function hci_read_remote_version(dd, handle, ver, to)
    ccall((:hci_read_remote_version, libbluetooth), Cint, (Cint, Cint, Ptr{hci_version}, Cint), dd, handle, ver, to)
end

function hci_read_remote_features(dd, handle, features, to)
    ccall((:hci_read_remote_features, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, features, to)
end

function hci_read_remote_ext_features(dd, handle, page, max_page, features, to)
    ccall((:hci_read_remote_ext_features, libbluetooth), Cint, (Cint, Cint, Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, handle, page, max_page, features, to)
end

function hci_read_clock_offset(dd, handle, clkoffset, to)
    ccall((:hci_read_clock_offset, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, clkoffset, to)
end

function hci_read_local_version(dd, ver, to)
    ccall((:hci_read_local_version, libbluetooth), Cint, (Cint, Ptr{hci_version}, Cint), dd, ver, to)
end

function hci_read_local_commands(dd, commands, to)
    ccall((:hci_read_local_commands, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, commands, to)
end

function hci_read_local_features(dd, features, to)
    ccall((:hci_read_local_features, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, features, to)
end

function hci_read_local_ext_features(dd, page, max_page, features, to)
    ccall((:hci_read_local_ext_features, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, page, max_page, features, to)
end

function hci_read_bd_addr(dd, bdaddr, to)
    ccall((:hci_read_bd_addr, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, bdaddr, to)
end

function hci_read_class_of_dev(dd, cls, to)
    ccall((:hci_read_class_of_dev, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, cls, to)
end

function hci_write_class_of_dev(dd, cls, to)
    ccall((:hci_write_class_of_dev, libbluetooth), Cint, (Cint, Cint, Cint), dd, cls, to)
end

function hci_read_voice_setting(dd, vs, to)
    ccall((:hci_read_voice_setting, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, vs, to)
end

function hci_write_voice_setting(dd, vs, to)
    ccall((:hci_write_voice_setting, libbluetooth), Cint, (Cint, Cint, Cint), dd, vs, to)
end

function hci_read_current_iac_lap(dd, num_iac, lap, to)
    ccall((:hci_read_current_iac_lap, libbluetooth), Cint, (Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, num_iac, lap, to)
end

function hci_write_current_iac_lap(dd, num_iac, lap, to)
    ccall((:hci_write_current_iac_lap, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, num_iac, lap, to)
end

function hci_read_stored_link_key(dd, bdaddr, all, to)
    ccall((:hci_read_stored_link_key, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint), dd, bdaddr, all, to)
end

function hci_write_stored_link_key(dd, bdaddr, key, to)
    ccall((:hci_write_stored_link_key, libbluetooth), Cint, (Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, bdaddr, key, to)
end

function hci_delete_stored_link_key(dd, bdaddr, all, to)
    ccall((:hci_delete_stored_link_key, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint), dd, bdaddr, all, to)
end

function hci_authenticate_link(dd, handle, to)
    ccall((:hci_authenticate_link, libbluetooth), Cint, (Cint, Cint, Cint), dd, handle, to)
end

function hci_encrypt_link(dd, handle, encrypt, to)
    ccall((:hci_encrypt_link, libbluetooth), Cint, (Cint, Cint, Cint, Cint), dd, handle, encrypt, to)
end

function hci_change_link_key(dd, handle, to)
    ccall((:hci_change_link_key, libbluetooth), Cint, (Cint, Cint, Cint), dd, handle, to)
end

function hci_switch_role(dd, bdaddr, role, to)
    ccall((:hci_switch_role, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint), dd, bdaddr, role, to)
end

function hci_park_mode(dd, handle, max_interval, min_interval, to)
    ccall((:hci_park_mode, libbluetooth), Cint, (Cint, Cint, Cint, Cint, Cint), dd, handle, max_interval, min_interval, to)
end

function hci_exit_park_mode(dd, handle, to)
    ccall((:hci_exit_park_mode, libbluetooth), Cint, (Cint, Cint, Cint), dd, handle, to)
end

function hci_read_inquiry_scan_type(dd, type, to)
    ccall((:hci_read_inquiry_scan_type, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, type, to)
end

function hci_write_inquiry_scan_type(dd, type, to)
    ccall((:hci_write_inquiry_scan_type, libbluetooth), Cint, (Cint, Cint, Cint), dd, type, to)
end

function hci_read_inquiry_mode(dd, mode, to)
    ccall((:hci_read_inquiry_mode, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, mode, to)
end

function hci_write_inquiry_mode(dd, mode, to)
    ccall((:hci_write_inquiry_mode, libbluetooth), Cint, (Cint, Cint, Cint), dd, mode, to)
end

function hci_read_afh_mode(dd, mode, to)
    ccall((:hci_read_afh_mode, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, mode, to)
end

function hci_write_afh_mode(dd, mode, to)
    ccall((:hci_write_afh_mode, libbluetooth), Cint, (Cint, Cint, Cint), dd, mode, to)
end

function hci_read_ext_inquiry_response(dd, fec, data, to)
    ccall((:hci_read_ext_inquiry_response, libbluetooth), Cint, (Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, fec, data, to)
end

function hci_write_ext_inquiry_response(dd, fec, data, to)
    ccall((:hci_write_ext_inquiry_response, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, fec, data, to)
end

function hci_read_simple_pairing_mode(dd, mode, to)
    ccall((:hci_read_simple_pairing_mode, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, mode, to)
end

function hci_write_simple_pairing_mode(dd, mode, to)
    ccall((:hci_write_simple_pairing_mode, libbluetooth), Cint, (Cint, Cint, Cint), dd, mode, to)
end

function hci_read_local_oob_data(dd, hash, randomizer, to)
    ccall((:hci_read_local_oob_data, libbluetooth), Cint, (Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, hash, randomizer, to)
end

function hci_read_inq_response_tx_power_level(dd, level, to)
    ccall((:hci_read_inq_response_tx_power_level, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, level, to)
end

function hci_read_inquiry_transmit_power_level(dd, level, to)
    ccall((:hci_read_inquiry_transmit_power_level, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, level, to)
end

function hci_write_inquiry_transmit_power_level(dd, level, to)
    ccall((:hci_write_inquiry_transmit_power_level, libbluetooth), Cint, (Cint, Cint, Cint), dd, level, to)
end

function hci_read_transmit_power_level(dd, handle, type, level, to)
    ccall((:hci_read_transmit_power_level, libbluetooth), Cint, (Cint, Cint, Cint, Ptr{Cint}, Cint), dd, handle, type, level, to)
end

function hci_read_link_policy(dd, handle, policy, to)
    ccall((:hci_read_link_policy, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, policy, to)
end

function hci_write_link_policy(dd, handle, policy, to)
    ccall((:hci_write_link_policy, libbluetooth), Cint, (Cint, Cint, Cint, Cint), dd, handle, policy, to)
end

function hci_read_link_supervision_timeout(dd, handle, timeout, to)
    ccall((:hci_read_link_supervision_timeout, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, timeout, to)
end

function hci_write_link_supervision_timeout(dd, handle, timeout, to)
    ccall((:hci_write_link_supervision_timeout, libbluetooth), Cint, (Cint, Cint, Cint, Cint), dd, handle, timeout, to)
end

function hci_set_afh_classification(dd, map, to)
    ccall((:hci_set_afh_classification, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, map, to)
end

function hci_read_link_quality(dd, handle, link_quality, to)
    ccall((:hci_read_link_quality, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, link_quality, to)
end

function hci_read_rssi(dd, handle, rssi, to)
    ccall((:hci_read_rssi, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, rssi, to)
end

function hci_read_afh_map(dd, handle, mode, map, to)
    ccall((:hci_read_afh_map, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, handle, mode, map, to)
end

function hci_read_clock(dd, handle, which, clock, accuracy, to)
    ccall((:hci_read_clock, libbluetooth), Cint, (Cint, Cint, Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, handle, which, clock, accuracy, to)
end

function hci_le_set_scan_enable(dev_id, enable, filter_dup, to)
    ccall((:hci_le_set_scan_enable, libbluetooth), Cint, (Cint, Cint, Cint, Cint), dev_id, enable, filter_dup, to)
end

function hci_le_set_scan_parameters(dev_id, type, interval, window, own_type, filter, to)
    ccall((:hci_le_set_scan_parameters, libbluetooth), Cint, (Cint, Cint, Cint, Cint, Cint, Cint, Cint), dev_id, type, interval, window, own_type, filter, to)
end

function hci_le_set_advertise_enable(dev_id, enable, to)
    ccall((:hci_le_set_advertise_enable, libbluetooth), Cint, (Cint, Cint, Cint), dev_id, enable, to)
end

function hci_le_create_conn(dd, interval, window, initiator_filter, peer_bdaddr_type, peer_bdaddr, own_bdaddr_type, min_interval, max_interval, latency, supervision_timeout, min_ce_length, max_ce_length, handle, to)
    ccall((:hci_le_create_conn, libbluetooth), Cint, (Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint, Ptr{Cint}, Cint), dd, interval, window, initiator_filter, peer_bdaddr_type, peer_bdaddr, own_bdaddr_type, min_interval, max_interval, latency, supervision_timeout, min_ce_length, max_ce_length, handle, to)
end

function hci_le_conn_update(dd, handle, min_interval, max_interval, latency, supervision_timeout, to)
    ccall((:hci_le_conn_update, libbluetooth), Cint, (Cint, Cint, Cint, Cint, Cint, Cint, Cint), dd, handle, min_interval, max_interval, latency, supervision_timeout, to)
end

function hci_le_add_white_list(dd, bdaddr, type, to)
    ccall((:hci_le_add_white_list, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint), dd, bdaddr, type, to)
end

function hci_le_rm_white_list(dd, bdaddr, type, to)
    ccall((:hci_le_rm_white_list, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint), dd, bdaddr, type, to)
end

function hci_le_read_white_list_size(dd, size, to)
    ccall((:hci_le_read_white_list_size, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, size, to)
end

function hci_le_clear_white_list(dd, to)
    ccall((:hci_le_clear_white_list, libbluetooth), Cint, (Cint, Cint), dd, to)
end

function hci_le_add_resolving_list(dd, bdaddr, type, peer_irk, local_irk, to)
    ccall((:hci_le_add_resolving_list, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Ptr{Cint}, Ptr{Cint}, Cint), dd, bdaddr, type, peer_irk, local_irk, to)
end

function hci_le_rm_resolving_list(dd, bdaddr, type, to)
    ccall((:hci_le_rm_resolving_list, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint, Cint), dd, bdaddr, type, to)
end

function hci_le_clear_resolving_list(dd, to)
    ccall((:hci_le_clear_resolving_list, libbluetooth), Cint, (Cint, Cint), dd, to)
end

function hci_le_read_resolving_list_size(dd, size, to)
    ccall((:hci_le_read_resolving_list_size, libbluetooth), Cint, (Cint, Ptr{Cint}, Cint), dd, size, to)
end

function hci_le_set_address_resolution_enable(dev_id, enable, to)
    ccall((:hci_le_set_address_resolution_enable, libbluetooth), Cint, (Cint, Cint, Cint), dev_id, enable, to)
end

function hci_le_read_remote_features(dd, handle, features, to)
    ccall((:hci_le_read_remote_features, libbluetooth), Cint, (Cint, Cint, Ptr{Cint}, Cint), dd, handle, features, to)
end

function hci_for_each_dev(flag, func, arg)
    ccall((:hci_for_each_dev, libbluetooth), Cint, (Cint, Ptr{Cvoid}, Clong), flag, func, arg)
end

function hci_get_route(bdaddr)
    ccall((:hci_get_route, libbluetooth), Cint, (Ptr{Cint},), bdaddr)
end

function hci_bustostr(bus)
    ccall((:hci_bustostr, libbluetooth), Ptr{Cchar}, (Cint,), bus)
end

function hci_typetostr(type)
    ccall((:hci_typetostr, libbluetooth), Ptr{Cchar}, (Cint,), type)
end

function hci_dtypetostr(type)
    ccall((:hci_dtypetostr, libbluetooth), Ptr{Cchar}, (Cint,), type)
end

function hci_dflagstostr(flags)
    ccall((:hci_dflagstostr, libbluetooth), Ptr{Cchar}, (Cint,), flags)
end

function hci_ptypetostr(ptype)
    ccall((:hci_ptypetostr, libbluetooth), Ptr{Cchar}, (Cuint,), ptype)
end

function hci_strtoptype(str, val)
    ccall((:hci_strtoptype, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, val)
end

function hci_scoptypetostr(ptype)
    ccall((:hci_scoptypetostr, libbluetooth), Ptr{Cchar}, (Cuint,), ptype)
end

function hci_strtoscoptype(str, val)
    ccall((:hci_strtoscoptype, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, val)
end

function hci_lptostr(ptype)
    ccall((:hci_lptostr, libbluetooth), Ptr{Cchar}, (Cuint,), ptype)
end

function hci_strtolp(str, val)
    ccall((:hci_strtolp, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, val)
end

function hci_lmtostr(ptype)
    ccall((:hci_lmtostr, libbluetooth), Ptr{Cchar}, (Cuint,), ptype)
end

function hci_strtolm(str, val)
    ccall((:hci_strtolm, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, val)
end

function hci_cmdtostr(cmd)
    ccall((:hci_cmdtostr, libbluetooth), Ptr{Cchar}, (Cuint,), cmd)
end

function hci_commandstostr(commands, pref, width)
    ccall((:hci_commandstostr, libbluetooth), Ptr{Cchar}, (Ptr{Cint}, Ptr{Cchar}, Cint), commands, pref, width)
end

function hci_vertostr(ver)
    ccall((:hci_vertostr, libbluetooth), Ptr{Cchar}, (Cuint,), ver)
end

function hci_strtover(str, ver)
    ccall((:hci_strtover, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, ver)
end

function lmp_vertostr(ver)
    ccall((:lmp_vertostr, libbluetooth), Ptr{Cchar}, (Cuint,), ver)
end

function lmp_strtover(str, ver)
    ccall((:lmp_strtover, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, ver)
end

function pal_vertostr(ver)
    ccall((:pal_vertostr, libbluetooth), Ptr{Cchar}, (Cuint,), ver)
end

function pal_strtover(str, ver)
    ccall((:pal_strtover, libbluetooth), Cint, (Ptr{Cchar}, Ptr{Cuint}), str, ver)
end

function lmp_featurestostr(features, pref, width)
    ccall((:lmp_featurestostr, libbluetooth), Ptr{Cchar}, (Ptr{Cint}, Ptr{Cchar}, Cint), features, pref, width)
end

function hci_set_bit(nr, addr)
    ccall((:hci_set_bit, libbluetooth), Cvoid, (Cint, Ptr{Cvoid}), nr, addr)
end

function hci_clear_bit(nr, addr)
    ccall((:hci_clear_bit, libbluetooth), Cvoid, (Cint, Ptr{Cvoid}), nr, addr)
end

function hci_test_bit(nr, addr)
    ccall((:hci_test_bit, libbluetooth), Cint, (Cint, Ptr{Cvoid}), nr, addr)
end

function hci_filter_clear(f)
    ccall((:hci_filter_clear, libbluetooth), Cvoid, (Ptr{hci_filter},), f)
end

function hci_filter_set_ptype(t, f)
    ccall((:hci_filter_set_ptype, libbluetooth), Cvoid, (Cint, Ptr{hci_filter}), t, f)
end

function hci_filter_clear_ptype(t, f)
    ccall((:hci_filter_clear_ptype, libbluetooth), Cvoid, (Cint, Ptr{hci_filter}), t, f)
end

function hci_filter_test_ptype(t, f)
    ccall((:hci_filter_test_ptype, libbluetooth), Cint, (Cint, Ptr{hci_filter}), t, f)
end

function hci_filter_all_ptypes(f)
    ccall((:hci_filter_all_ptypes, libbluetooth), Cvoid, (Ptr{hci_filter},), f)
end

function hci_filter_set_event(e, f)
    ccall((:hci_filter_set_event, libbluetooth), Cvoid, (Cint, Ptr{hci_filter}), e, f)
end

function hci_filter_clear_event(e, f)
    ccall((:hci_filter_clear_event, libbluetooth), Cvoid, (Cint, Ptr{hci_filter}), e, f)
end

function hci_filter_test_event(e, f)
    ccall((:hci_filter_test_event, libbluetooth), Cint, (Cint, Ptr{hci_filter}), e, f)
end

function hci_filter_all_events(f)
    ccall((:hci_filter_all_events, libbluetooth), Cvoid, (Ptr{hci_filter},), f)
end

function hci_filter_set_opcode(opcode, f)
    ccall((:hci_filter_set_opcode, libbluetooth), Cvoid, (Cint, Ptr{hci_filter}), opcode, f)
end

function hci_filter_clear_opcode(f)
    ccall((:hci_filter_clear_opcode, libbluetooth), Cvoid, (Ptr{hci_filter},), f)
end

function hci_filter_test_opcode(opcode, f)
    ccall((:hci_filter_test_opcode, libbluetooth), Cint, (Cint, Ptr{hci_filter}), opcode, f)
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

const HCI_MAX_DEV = 16

const HCI_MAX_ACL_SIZE = 1492 + 4

const HCI_MAX_SCO_SIZE = 255

const HCI_MAX_EVENT_SIZE = 260

const HCI_MAX_FRAME_SIZE = HCI_MAX_ACL_SIZE + 4

const HCI_DEV_REG = 1

const HCI_DEV_UNREG = 2

const HCI_DEV_UP = 3

const HCI_DEV_DOWN = 4

const HCI_DEV_SUSPEND = 5

const HCI_DEV_RESUME = 6

const HCI_VIRTUAL = 0

const HCI_USB = 1

const HCI_PCCARD = 2

const HCI_UART = 3

const HCI_RS232 = 4

const HCI_PCI = 5

const HCI_SDIO = 6

const HCI_SPI = 7

const HCI_I2C = 8

const HCI_SMD = 9

const HCI_PRIMARY = 0x00

const HCI_AMP = 0x01

const HCI_BREDR = HCI_PRIMARY

const HCIDEVUP = _IOW(Cchar('H'), 201, Cint)

const HCIDEVDOWN = _IOW(Cchar('H'), 202, Cint)

const HCIDEVRESET = _IOW(Cchar('H'), 203, Cint)

const HCIDEVRESTAT = _IOW(Cchar('H'), 204, Cint)

const HCIGETDEVLIST = _IOR(Cchar('H'), 210, Cint)

const HCIGETDEVINFO = _IOR(Cchar('H'), 211, Cint)

const HCIGETCONNLIST = _IOR(Cchar('H'), 212, Cint)

const HCIGETCONNINFO = _IOR(Cchar('H'), 213, Cint)

const HCIGETAUTHINFO = _IOR(Cchar('H'), 215, Cint)

const HCISETRAW = _IOW(Cchar('H'), 220, Cint)

const HCISETSCAN = _IOW(Cchar('H'), 221, Cint)

const HCISETAUTH = _IOW(Cchar('H'), 222, Cint)

const HCISETENCRYPT = _IOW(Cchar('H'), 223, Cint)

const HCISETPTYPE = _IOW(Cchar('H'), 224, Cint)

const HCISETLINKPOL = _IOW(Cchar('H'), 225, Cint)

const HCISETLINKMODE = _IOW(Cchar('H'), 226, Cint)

const HCISETACLMTU = _IOW(Cchar('H'), 227, Cint)

const HCISETSCOMTU = _IOW(Cchar('H'), 228, Cint)

const HCIBLOCKADDR = _IOW(Cchar('H'), 230, Cint)

const HCIUNBLOCKADDR = _IOW(Cchar('H'), 231, Cint)

const HCIINQUIRY = _IOR(Cchar('H'), 240, Cint)

const HCI_COMMAND_PKT = 0x01

const HCI_ACLDATA_PKT = 0x02

const HCI_SCODATA_PKT = 0x03

const HCI_EVENT_PKT = 0x04

const HCI_VENDOR_PKT = 0xff

const HCI_2DH1 = 0x0002

const HCI_3DH1 = 0x0004

const HCI_DM1 = 0x0008

const HCI_DH1 = 0x0010

const HCI_2DH3 = 0x0100

const HCI_3DH3 = 0x0200

const HCI_DM3 = 0x0400

const HCI_DH3 = 0x0800

const HCI_2DH5 = 0x1000

const HCI_3DH5 = 0x2000

const HCI_DM5 = 0x4000

const HCI_DH5 = 0x8000

const HCI_HV1 = 0x0020

const HCI_HV2 = 0x0040

const HCI_HV3 = 0x0080

const HCI_EV3 = 0x0008

const HCI_EV4 = 0x0010

const HCI_EV5 = 0x0020

const HCI_2EV3 = 0x0040

const HCI_3EV3 = 0x0080

const HCI_2EV5 = 0x0100

const HCI_3EV5 = 0x0200

const SCO_PTYPE_MASK = (HCI_HV1 | HCI_HV2) | HCI_HV3

const ACL_PTYPE_MASK = ((((HCI_DM1 | HCI_DH1) | HCI_DM3) | HCI_DH3) | HCI_DM5) | HCI_DH5

const HCI_UNKNOWN_COMMAND = 0x01

const HCI_NO_CONNECTION = 0x02

const HCI_HARDWARE_FAILURE = 0x03

const HCI_PAGE_TIMEOUT = 0x04

const HCI_AUTHENTICATION_FAILURE = 0x05

const HCI_PIN_OR_KEY_MISSING = 0x06

const HCI_MEMORY_FULL = 0x07

const HCI_CONNECTION_TIMEOUT = 0x08

const HCI_MAX_NUMBER_OF_CONNECTIONS = 0x09

const HCI_MAX_NUMBER_OF_SCO_CONNECTIONS = 0x0a

const HCI_ACL_CONNECTION_EXISTS = 0x0b

const HCI_COMMAND_DISALLOWED = 0x0c

const HCI_REJECTED_LIMITED_RESOURCES = 0x0d

const HCI_REJECTED_SECURITY = 0x0e

const HCI_REJECTED_PERSONAL = 0x0f

const HCI_HOST_TIMEOUT = 0x10

const HCI_UNSUPPORTED_FEATURE = 0x11

const HCI_INVALID_PARAMETERS = 0x12

const HCI_OE_USER_ENDED_CONNECTION = 0x13

const HCI_OE_LOW_RESOURCES = 0x14

const HCI_OE_POWER_OFF = 0x15

const HCI_CONNECTION_TERMINATED = 0x16

const HCI_REPEATED_ATTEMPTS = 0x17

const HCI_PAIRING_NOT_ALLOWED = 0x18

const HCI_UNKNOWN_LMP_PDU = 0x19

const HCI_UNSUPPORTED_REMOTE_FEATURE = 0x1a

const HCI_SCO_OFFSET_REJECTED = 0x1b

const HCI_SCO_INTERVAL_REJECTED = 0x1c

const HCI_AIR_MODE_REJECTED = 0x1d

const HCI_INVALID_LMP_PARAMETERS = 0x1e

const HCI_UNSPECIFIED_ERROR = 0x1f

const HCI_UNSUPPORTED_LMP_PARAMETER_VALUE = 0x20

const HCI_ROLE_CHANGE_NOT_ALLOWED = 0x21

const HCI_LMP_RESPONSE_TIMEOUT = 0x22

const HCI_LMP_ERROR_TRANSACTION_COLLISION = 0x23

const HCI_LMP_PDU_NOT_ALLOWED = 0x24

const HCI_ENCRYPTION_MODE_NOT_ACCEPTED = 0x25

const HCI_UNIT_LINK_KEY_USED = 0x26

const HCI_QOS_NOT_SUPPORTED = 0x27

const HCI_INSTANT_PASSED = 0x28

const HCI_PAIRING_NOT_SUPPORTED = 0x29

const HCI_TRANSACTION_COLLISION = 0x2a

const HCI_QOS_UNACCEPTABLE_PARAMETER = 0x2c

const HCI_QOS_REJECTED = 0x2d

const HCI_CLASSIFICATION_NOT_SUPPORTED = 0x2e

const HCI_INSUFFICIENT_SECURITY = 0x2f

const HCI_PARAMETER_OUT_OF_RANGE = 0x30

const HCI_ROLE_SWITCH_PENDING = 0x32

const HCI_SLOT_VIOLATION = 0x34

const HCI_ROLE_SWITCH_FAILED = 0x35

const HCI_EIR_TOO_LARGE = 0x36

const HCI_SIMPLE_PAIRING_NOT_SUPPORTED = 0x37

const HCI_HOST_BUSY_PAIRING = 0x38

const ACL_START_NO_FLUSH = 0x00

const ACL_CONT = 0x01

const ACL_START = 0x02

const ACL_ACTIVE_BCAST = 0x04

const ACL_PICO_BCAST = 0x08

const SCO_LINK = 0x00

const ACL_LINK = 0x01

const ESCO_LINK = 0x02

const LMP_3SLOT = 0x01

const LMP_5SLOT = 0x02

const LMP_ENCRYPT = 0x04

const LMP_SOFFSET = 0x08

const LMP_TACCURACY = 0x10

const LMP_RSWITCH = 0x20

const LMP_HOLD = 0x40

const LMP_SNIFF = 0x80

const LMP_PARK = 0x01

const LMP_RSSI = 0x02

const LMP_QUALITY = 0x04

const LMP_SCO = 0x08

const LMP_HV2 = 0x10

const LMP_HV3 = 0x20

const LMP_ULAW = 0x40

const LMP_ALAW = 0x80

const LMP_CVSD = 0x01

const LMP_PSCHEME = 0x02

const LMP_PCONTROL = 0x04

const LMP_TRSP_SCO = 0x08

const LMP_BCAST_ENC = 0x80

const LMP_EDR_ACL_2M = 0x02

const LMP_EDR_ACL_3M = 0x04

const LMP_ENH_ISCAN = 0x08

const LMP_ILACE_ISCAN = 0x10

const LMP_ILACE_PSCAN = 0x20

const LMP_RSSI_INQ = 0x40

const LMP_ESCO = 0x80

const LMP_EV4 = 0x01

const LMP_EV5 = 0x02

const LMP_AFH_CAP_SLV = 0x08

const LMP_AFH_CLS_SLV = 0x10

const LMP_NO_BREDR = 0x20

const LMP_LE = 0x40

const LMP_EDR_3SLOT = 0x80

const LMP_EDR_5SLOT = 0x01

const LMP_SNIFF_SUBR = 0x02

const LMP_PAUSE_ENC = 0x04

const LMP_AFH_CAP_MST = 0x08

const LMP_AFH_CLS_MST = 0x10

const LMP_EDR_ESCO_2M = 0x20

const LMP_EDR_ESCO_3M = 0x40

const LMP_EDR_3S_ESCO = 0x80

const LMP_EXT_INQ = 0x01

const LMP_LE_BREDR = 0x02

const LMP_SIMPLE_PAIR = 0x08

const LMP_ENCAPS_PDU = 0x10

const LMP_ERR_DAT_REP = 0x20

const LMP_NFLUSH_PKTS = 0x40

const LMP_LSTO = 0x01

const LMP_INQ_TX_PWR = 0x02

const LMP_EPC = 0x04

const LMP_EXT_FEAT = 0x80

const LMP_HOST_SSP = 0x01

const LMP_HOST_LE = 0x02

const LMP_HOST_LE_BREDR = 0x04

const HCI_LP_RSWITCH = 0x0001

const HCI_LP_HOLD = 0x0002

const HCI_LP_SNIFF = 0x0004

const HCI_LP_PARK = 0x0008

const HCI_LM_ACCEPT = 0x8000

const HCI_LM_MASTER = 0x0001

const HCI_LM_AUTH = 0x0002

const HCI_LM_ENCRYPT = 0x0004

const HCI_LM_TRUSTED = 0x0008

const HCI_LM_RELIABLE = 0x0010

const HCI_LM_SECURE = 0x0020

const HCI_LK_COMBINATION = 0x00

const HCI_LK_LOCAL_UNIT = 0x01

const HCI_LK_REMOTE_UNIT = 0x02

const HCI_LK_DEBUG_COMBINATION = 0x03

const HCI_LK_UNAUTH_COMBINATION = 0x04

const HCI_LK_AUTH_COMBINATION = 0x05

const HCI_LK_CHANGED_COMBINATION = 0x06

const HCI_LK_INVALID = 0xff

const OGF_LINK_CTL = 0x01

const OCF_INQUIRY = 0x0001

const INQUIRY_CP_SIZE = 5

const STATUS_BDADDR_RP_SIZE = 7

const OCF_INQUIRY_CANCEL = 0x0002

const OCF_PERIODIC_INQUIRY = 0x0003

const PERIODIC_INQUIRY_CP_SIZE = 9

const OCF_EXIT_PERIODIC_INQUIRY = 0x0004

const OCF_CREATE_CONN = 0x0005

const CREATE_CONN_CP_SIZE = 13

const OCF_DISCONNECT = 0x0006

const DISCONNECT_CP_SIZE = 3

const OCF_ADD_SCO = 0x0007

const ADD_SCO_CP_SIZE = 4

const OCF_CREATE_CONN_CANCEL = 0x0008

const CREATE_CONN_CANCEL_CP_SIZE = 6

const OCF_ACCEPT_CONN_REQ = 0x0009

const ACCEPT_CONN_REQ_CP_SIZE = 7

const OCF_REJECT_CONN_REQ = 0x000a

const REJECT_CONN_REQ_CP_SIZE = 7

const OCF_LINK_KEY_REPLY = 0x000b

const LINK_KEY_REPLY_CP_SIZE = 22

const OCF_LINK_KEY_NEG_REPLY = 0x000c

const OCF_PIN_CODE_REPLY = 0x000d

const PIN_CODE_REPLY_CP_SIZE = 23

const OCF_PIN_CODE_NEG_REPLY = 0x000e

const OCF_SET_CONN_PTYPE = 0x000f

const SET_CONN_PTYPE_CP_SIZE = 4

const OCF_AUTH_REQUESTED = 0x0011

const AUTH_REQUESTED_CP_SIZE = 2

const OCF_SET_CONN_ENCRYPT = 0x0013

const SET_CONN_ENCRYPT_CP_SIZE = 3

const OCF_CHANGE_CONN_LINK_KEY = 0x0015

const CHANGE_CONN_LINK_KEY_CP_SIZE = 2

const OCF_MASTER_LINK_KEY = 0x0017

const MASTER_LINK_KEY_CP_SIZE = 1

const OCF_REMOTE_NAME_REQ = 0x0019

const REMOTE_NAME_REQ_CP_SIZE = 10

const OCF_REMOTE_NAME_REQ_CANCEL = 0x001a

const REMOTE_NAME_REQ_CANCEL_CP_SIZE = 6

const OCF_READ_REMOTE_FEATURES = 0x001b

const READ_REMOTE_FEATURES_CP_SIZE = 2

const OCF_READ_REMOTE_EXT_FEATURES = 0x001c

const READ_REMOTE_EXT_FEATURES_CP_SIZE = 3

const OCF_READ_REMOTE_VERSION = 0x001d

const READ_REMOTE_VERSION_CP_SIZE = 2

const OCF_READ_CLOCK_OFFSET = 0x001f

const READ_CLOCK_OFFSET_CP_SIZE = 2

const OCF_READ_LMP_HANDLE = 0x0020

const OCF_SETUP_SYNC_CONN = 0x0028

const SETUP_SYNC_CONN_CP_SIZE = 17

const OCF_ACCEPT_SYNC_CONN_REQ = 0x0029

const ACCEPT_SYNC_CONN_REQ_CP_SIZE = 21

const OCF_REJECT_SYNC_CONN_REQ = 0x002a

const REJECT_SYNC_CONN_REQ_CP_SIZE = 7

const OCF_IO_CAPABILITY_REPLY = 0x002b

const IO_CAPABILITY_REPLY_CP_SIZE = 9

const OCF_USER_CONFIRM_REPLY = 0x002c

const USER_CONFIRM_REPLY_CP_SIZE = 6

const OCF_USER_CONFIRM_NEG_REPLY = 0x002d

const OCF_USER_PASSKEY_REPLY = 0x002e

const USER_PASSKEY_REPLY_CP_SIZE = 10

const OCF_USER_PASSKEY_NEG_REPLY = 0x002f

const OCF_REMOTE_OOB_DATA_REPLY = 0x0030

const REMOTE_OOB_DATA_REPLY_CP_SIZE = 38

const OCF_REMOTE_OOB_DATA_NEG_REPLY = 0x0033

const OCF_IO_CAPABILITY_NEG_REPLY = 0x0034

const IO_CAPABILITY_NEG_REPLY_CP_SIZE = 7

const OCF_CREATE_PHYSICAL_LINK = 0x0035

const CREATE_PHYSICAL_LINK_CP_SIZE = 35

const OCF_ACCEPT_PHYSICAL_LINK = 0x0036

const ACCEPT_PHYSICAL_LINK_CP_SIZE = 35

const OCF_DISCONNECT_PHYSICAL_LINK = 0x0037

const DISCONNECT_PHYSICAL_LINK_CP_SIZE = 2

const OCF_CREATE_LOGICAL_LINK = 0x0038

const CREATE_LOGICAL_LINK_CP_SIZE = 33

const OCF_ACCEPT_LOGICAL_LINK = 0x0039

const OCF_DISCONNECT_LOGICAL_LINK = 0x003a

const DISCONNECT_LOGICAL_LINK_CP_SIZE = 2

const OCF_LOGICAL_LINK_CANCEL = 0x003b

const LOGICAL_LINK_CANCEL_CP_SIZE = 2

const LOGICAL_LINK_CANCEL_RP_SIZE = 3

const OCF_FLOW_SPEC_MODIFY = 0x003c

const OGF_LINK_POLICY = 0x02

const OCF_HOLD_MODE = 0x0001

const HOLD_MODE_CP_SIZE = 6

const OCF_SNIFF_MODE = 0x0003

const SNIFF_MODE_CP_SIZE = 10

const OCF_EXIT_SNIFF_MODE = 0x0004

const EXIT_SNIFF_MODE_CP_SIZE = 2

const OCF_PARK_MODE = 0x0005

const PARK_MODE_CP_SIZE = 6

const OCF_EXIT_PARK_MODE = 0x0006

const EXIT_PARK_MODE_CP_SIZE = 2

const OCF_QOS_SETUP = 0x0007

const HCI_QOS_CP_SIZE = 17

const QOS_SETUP_CP_SIZE = 3 + HCI_QOS_CP_SIZE

const OCF_ROLE_DISCOVERY = 0x0009

const ROLE_DISCOVERY_CP_SIZE = 2

const ROLE_DISCOVERY_RP_SIZE = 4

const OCF_SWITCH_ROLE = 0x000b

const SWITCH_ROLE_CP_SIZE = 7

const OCF_READ_LINK_POLICY = 0x000c

const READ_LINK_POLICY_CP_SIZE = 2

const READ_LINK_POLICY_RP_SIZE = 5

const OCF_WRITE_LINK_POLICY = 0x000d

const WRITE_LINK_POLICY_CP_SIZE = 4

const WRITE_LINK_POLICY_RP_SIZE = 3

const OCF_READ_DEFAULT_LINK_POLICY = 0x000e

const OCF_WRITE_DEFAULT_LINK_POLICY = 0x000f

const OCF_FLOW_SPECIFICATION = 0x0010

const OCF_SNIFF_SUBRATING = 0x0011

const SNIFF_SUBRATING_CP_SIZE = 8

const OGF_HOST_CTL = 0x03

const OCF_SET_EVENT_MASK = 0x0001

const SET_EVENT_MASK_CP_SIZE = 8

const OCF_RESET = 0x0003

const OCF_SET_EVENT_FLT = 0x0005

const SET_EVENT_FLT_CP_SIZE = 2

const FLT_CLEAR_ALL = 0x00

const FLT_INQ_RESULT = 0x01

const FLT_CONN_SETUP = 0x02

const INQ_RESULT_RETURN_ALL = 0x00

const INQ_RESULT_RETURN_CLASS = 0x01

const INQ_RESULT_RETURN_BDADDR = 0x02

const CONN_SETUP_ALLOW_ALL = 0x00

const CONN_SETUP_ALLOW_CLASS = 0x01

const CONN_SETUP_ALLOW_BDADDR = 0x02

const CONN_SETUP_AUTO_OFF = 0x01

const CONN_SETUP_AUTO_ON = 0x02

const OCF_FLUSH = 0x0008

const OCF_READ_PIN_TYPE = 0x0009

const READ_PIN_TYPE_RP_SIZE = 2

const OCF_WRITE_PIN_TYPE = 0x000a

const WRITE_PIN_TYPE_CP_SIZE = 1

const OCF_CREATE_NEW_UNIT_KEY = 0x000b

const OCF_READ_STORED_LINK_KEY = 0x000d

const READ_STORED_LINK_KEY_CP_SIZE = 7

const READ_STORED_LINK_KEY_RP_SIZE = 5

const OCF_WRITE_STORED_LINK_KEY = 0x0011

const WRITE_STORED_LINK_KEY_CP_SIZE = 1

const READ_WRITE_LINK_KEY_RP_SIZE = 2

const OCF_DELETE_STORED_LINK_KEY = 0x0012

const DELETE_STORED_LINK_KEY_CP_SIZE = 7

const DELETE_STORED_LINK_KEY_RP_SIZE = 3

const HCI_MAX_NAME_LENGTH = 248

const OCF_CHANGE_LOCAL_NAME = 0x0013

const CHANGE_LOCAL_NAME_CP_SIZE = 248

const OCF_READ_LOCAL_NAME = 0x0014

const READ_LOCAL_NAME_RP_SIZE = 249

const OCF_READ_CONN_ACCEPT_TIMEOUT = 0x0015

const READ_CONN_ACCEPT_TIMEOUT_RP_SIZE = 3

const OCF_WRITE_CONN_ACCEPT_TIMEOUT = 0x0016

const WRITE_CONN_ACCEPT_TIMEOUT_CP_SIZE = 2

const OCF_READ_PAGE_TIMEOUT = 0x0017

const READ_PAGE_TIMEOUT_RP_SIZE = 3

const OCF_WRITE_PAGE_TIMEOUT = 0x0018

const WRITE_PAGE_TIMEOUT_CP_SIZE = 2

const OCF_READ_SCAN_ENABLE = 0x0019

const READ_SCAN_ENABLE_RP_SIZE = 2

const OCF_WRITE_SCAN_ENABLE = 0x001a

const SCAN_DISABLED = 0x00

const SCAN_INQUIRY = 0x01

const SCAN_PAGE = 0x02

const OCF_READ_PAGE_ACTIVITY = 0x001b

const READ_PAGE_ACTIVITY_RP_SIZE = 5

const OCF_WRITE_PAGE_ACTIVITY = 0x001c

const WRITE_PAGE_ACTIVITY_CP_SIZE = 4

const OCF_READ_INQ_ACTIVITY = 0x001d

const READ_INQ_ACTIVITY_RP_SIZE = 5

const OCF_WRITE_INQ_ACTIVITY = 0x001e

const WRITE_INQ_ACTIVITY_CP_SIZE = 4

const OCF_READ_AUTH_ENABLE = 0x001f

const OCF_WRITE_AUTH_ENABLE = 0x0020

const AUTH_DISABLED = 0x00

const AUTH_ENABLED = 0x01

const OCF_READ_ENCRYPT_MODE = 0x0021

const OCF_WRITE_ENCRYPT_MODE = 0x0022

const ENCRYPT_DISABLED = 0x00

const ENCRYPT_P2P = 0x01

const ENCRYPT_BOTH = 0x02

const OCF_READ_CLASS_OF_DEV = 0x0023

const READ_CLASS_OF_DEV_RP_SIZE = 4

const OCF_WRITE_CLASS_OF_DEV = 0x0024

const WRITE_CLASS_OF_DEV_CP_SIZE = 3

const OCF_READ_VOICE_SETTING = 0x0025

const READ_VOICE_SETTING_RP_SIZE = 3

const OCF_WRITE_VOICE_SETTING = 0x0026

const WRITE_VOICE_SETTING_CP_SIZE = 2

const OCF_READ_AUTOMATIC_FLUSH_TIMEOUT = 0x0027

const OCF_WRITE_AUTOMATIC_FLUSH_TIMEOUT = 0x0028

const OCF_READ_NUM_BROADCAST_RETRANS = 0x0029

const OCF_WRITE_NUM_BROADCAST_RETRANS = 0x002a

const OCF_READ_HOLD_MODE_ACTIVITY = 0x002b

const OCF_WRITE_HOLD_MODE_ACTIVITY = 0x002c

const OCF_READ_TRANSMIT_POWER_LEVEL = 0x002d

const READ_TRANSMIT_POWER_LEVEL_CP_SIZE = 3

const READ_TRANSMIT_POWER_LEVEL_RP_SIZE = 4

const OCF_READ_SYNC_FLOW_ENABLE = 0x002e

const OCF_WRITE_SYNC_FLOW_ENABLE = 0x002f

const OCF_SET_CONTROLLER_TO_HOST_FC = 0x0031

const OCF_HOST_BUFFER_SIZE = 0x0033

const HOST_BUFFER_SIZE_CP_SIZE = 7

const OCF_HOST_NUM_COMP_PKTS = 0x0035

const HOST_NUM_COMP_PKTS_CP_SIZE = 1

const OCF_READ_LINK_SUPERVISION_TIMEOUT = 0x0036

const READ_LINK_SUPERVISION_TIMEOUT_RP_SIZE = 5

const OCF_WRITE_LINK_SUPERVISION_TIMEOUT = 0x0037

const WRITE_LINK_SUPERVISION_TIMEOUT_CP_SIZE = 4

const WRITE_LINK_SUPERVISION_TIMEOUT_RP_SIZE = 3

const OCF_READ_NUM_SUPPORTED_IAC = 0x0038

const MAX_IAC_LAP = 0x40

const OCF_READ_CURRENT_IAC_LAP = 0x0039

const READ_CURRENT_IAC_LAP_RP_SIZE = 2 + 3MAX_IAC_LAP

const OCF_WRITE_CURRENT_IAC_LAP = 0x003a

const WRITE_CURRENT_IAC_LAP_CP_SIZE = 1 + 3MAX_IAC_LAP

const OCF_READ_PAGE_SCAN_PERIOD_MODE = 0x003b

const OCF_WRITE_PAGE_SCAN_PERIOD_MODE = 0x003c

const OCF_READ_PAGE_SCAN_MODE = 0x003d

const OCF_WRITE_PAGE_SCAN_MODE = 0x003e

const OCF_SET_AFH_CLASSIFICATION = 0x003f

const SET_AFH_CLASSIFICATION_CP_SIZE = 10

const SET_AFH_CLASSIFICATION_RP_SIZE = 1

const OCF_READ_INQUIRY_SCAN_TYPE = 0x0042

const READ_INQUIRY_SCAN_TYPE_RP_SIZE = 2

const OCF_WRITE_INQUIRY_SCAN_TYPE = 0x0043

const WRITE_INQUIRY_SCAN_TYPE_CP_SIZE = 1

const WRITE_INQUIRY_SCAN_TYPE_RP_SIZE = 1

const OCF_READ_INQUIRY_MODE = 0x0044

const READ_INQUIRY_MODE_RP_SIZE = 2

const OCF_WRITE_INQUIRY_MODE = 0x0045

const WRITE_INQUIRY_MODE_CP_SIZE = 1

const WRITE_INQUIRY_MODE_RP_SIZE = 1

const OCF_READ_PAGE_SCAN_TYPE = 0x0046

const OCF_WRITE_PAGE_SCAN_TYPE = 0x0047

const PAGE_SCAN_TYPE_STANDARD = 0x00

const PAGE_SCAN_TYPE_INTERLACED = 0x01

const OCF_READ_AFH_MODE = 0x0048

const READ_AFH_MODE_RP_SIZE = 2

const OCF_WRITE_AFH_MODE = 0x0049

const WRITE_AFH_MODE_CP_SIZE = 1

const WRITE_AFH_MODE_RP_SIZE = 1

const HCI_MAX_EIR_LENGTH = 240

const OCF_READ_EXT_INQUIRY_RESPONSE = 0x0051

const READ_EXT_INQUIRY_RESPONSE_RP_SIZE = 242

const OCF_WRITE_EXT_INQUIRY_RESPONSE = 0x0052

const WRITE_EXT_INQUIRY_RESPONSE_CP_SIZE = 241

const WRITE_EXT_INQUIRY_RESPONSE_RP_SIZE = 1

const OCF_REFRESH_ENCRYPTION_KEY = 0x0053

const REFRESH_ENCRYPTION_KEY_CP_SIZE = 2

const REFRESH_ENCRYPTION_KEY_RP_SIZE = 1

const OCF_READ_SIMPLE_PAIRING_MODE = 0x0055

const READ_SIMPLE_PAIRING_MODE_RP_SIZE = 2

const OCF_WRITE_SIMPLE_PAIRING_MODE = 0x0056

const WRITE_SIMPLE_PAIRING_MODE_CP_SIZE = 1

const WRITE_SIMPLE_PAIRING_MODE_RP_SIZE = 1

const OCF_READ_LOCAL_OOB_DATA = 0x0057

const READ_LOCAL_OOB_DATA_RP_SIZE = 33

const OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL = 0x0058

const READ_INQ_RESPONSE_TX_POWER_LEVEL_RP_SIZE = 2

const OCF_READ_INQUIRY_TRANSMIT_POWER_LEVEL = 0x0058

const READ_INQUIRY_TRANSMIT_POWER_LEVEL_RP_SIZE = 2

const OCF_WRITE_INQUIRY_TRANSMIT_POWER_LEVEL = 0x0059

const WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_CP_SIZE = 1

const WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_RP_SIZE = 1

const OCF_READ_DEFAULT_ERROR_DATA_REPORTING = 0x005a

const READ_DEFAULT_ERROR_DATA_REPORTING_RP_SIZE = 2

const OCF_WRITE_DEFAULT_ERROR_DATA_REPORTING = 0x005b

const WRITE_DEFAULT_ERROR_DATA_REPORTING_CP_SIZE = 1

const WRITE_DEFAULT_ERROR_DATA_REPORTING_RP_SIZE = 1

const OCF_ENHANCED_FLUSH = 0x005f

const ENHANCED_FLUSH_CP_SIZE = 3

const OCF_SEND_KEYPRESS_NOTIFY = 0x0060

const SEND_KEYPRESS_NOTIFY_CP_SIZE = 7

const SEND_KEYPRESS_NOTIFY_RP_SIZE = 1

const OCF_READ_LOGICAL_LINK_ACCEPT_TIMEOUT = 0x0061

const READ_LOGICAL_LINK_ACCEPT_TIMEOUT_RP_SIZE = 3

const OCF_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT = 0x0062

const WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_CP_SIZE = 2

const OCF_SET_EVENT_MASK_PAGE_2 = 0x0063

const OCF_READ_LOCATION_DATA = 0x0064

const OCF_WRITE_LOCATION_DATA = 0x0065

const OCF_READ_FLOW_CONTROL_MODE = 0x0066

const OCF_WRITE_FLOW_CONTROL_MODE = 0x0067

const OCF_READ_ENHANCED_TRANSMIT_POWER_LEVEL = 0x0068

const READ_ENHANCED_TRANSMIT_POWER_LEVEL_RP_SIZE = 6

const OCF_READ_BEST_EFFORT_FLUSH_TIMEOUT = 0x0069

const READ_BEST_EFFORT_FLUSH_TIMEOUT_RP_SIZE = 5

const OCF_WRITE_BEST_EFFORT_FLUSH_TIMEOUT = 0x006a

const WRITE_BEST_EFFORT_FLUSH_TIMEOUT_CP_SIZE = 6

const WRITE_BEST_EFFORT_FLUSH_TIMEOUT_RP_SIZE = 1

const OCF_READ_LE_HOST_SUPPORTED = 0x006c

const READ_LE_HOST_SUPPORTED_RP_SIZE = 3

const OCF_WRITE_LE_HOST_SUPPORTED = 0x006d

const WRITE_LE_HOST_SUPPORTED_CP_SIZE = 2

const OGF_INFO_PARAM = 0x04

const OCF_READ_LOCAL_VERSION = 0x0001

const READ_LOCAL_VERSION_RP_SIZE = 9

const OCF_READ_LOCAL_COMMANDS = 0x0002

const READ_LOCAL_COMMANDS_RP_SIZE = 65

const OCF_READ_LOCAL_FEATURES = 0x0003

const READ_LOCAL_FEATURES_RP_SIZE = 9

const OCF_READ_LOCAL_EXT_FEATURES = 0x0004

const READ_LOCAL_EXT_FEATURES_CP_SIZE = 1

const READ_LOCAL_EXT_FEATURES_RP_SIZE = 11

const OCF_READ_BUFFER_SIZE = 0x0005

const READ_BUFFER_SIZE_RP_SIZE = 8

const OCF_READ_COUNTRY_CODE = 0x0007

const OCF_READ_BD_ADDR = 0x0009

const READ_BD_ADDR_RP_SIZE = 7

const OCF_READ_DATA_BLOCK_SIZE = 0x000a

const OGF_STATUS_PARAM = 0x05

const OCF_READ_FAILED_CONTACT_COUNTER = 0x0001

const READ_FAILED_CONTACT_COUNTER_RP_SIZE = 4

const OCF_RESET_FAILED_CONTACT_COUNTER = 0x0002

const RESET_FAILED_CONTACT_COUNTER_RP_SIZE = 3

const OCF_READ_LINK_QUALITY = 0x0003

const READ_LINK_QUALITY_RP_SIZE = 4

const OCF_READ_RSSI = 0x0005

const READ_RSSI_RP_SIZE = 4

const OCF_READ_AFH_MAP = 0x0006

const READ_AFH_MAP_RP_SIZE = 14

const OCF_READ_CLOCK = 0x0007

const READ_CLOCK_CP_SIZE = 3

const READ_CLOCK_RP_SIZE = 9

const OCF_READ_LOCAL_AMP_INFO = 0x0009

const READ_LOCAL_AMP_INFO_RP_SIZE = 31

const OCF_READ_LOCAL_AMP_ASSOC = 0x000a

const READ_LOCAL_AMP_ASSOC_CP_SIZE = 5

const READ_LOCAL_AMP_ASSOC_RP_SIZE = 252

const OCF_WRITE_REMOTE_AMP_ASSOC = 0x000b

const WRITE_REMOTE_AMP_ASSOC_CP_SIZE = 253

const WRITE_REMOTE_AMP_ASSOC_RP_SIZE = 2

const OGF_TESTING_CMD = 0x3e

const OCF_READ_LOOPBACK_MODE = 0x0001

const OCF_WRITE_LOOPBACK_MODE = 0x0002

const OCF_ENABLE_DEVICE_UNDER_TEST_MODE = 0x0003

const OCF_WRITE_SIMPLE_PAIRING_DEBUG_MODE = 0x0004

const WRITE_SIMPLE_PAIRING_DEBUG_MODE_CP_SIZE = 1

const WRITE_SIMPLE_PAIRING_DEBUG_MODE_RP_SIZE = 1

const OGF_LE_CTL = 0x08

const OCF_LE_SET_EVENT_MASK = 0x0001

const LE_SET_EVENT_MASK_CP_SIZE = 8

const OCF_LE_READ_BUFFER_SIZE = 0x0002

const LE_READ_BUFFER_SIZE_RP_SIZE = 4

const OCF_LE_READ_LOCAL_SUPPORTED_FEATURES = 0x0003

const LE_READ_LOCAL_SUPPORTED_FEATURES_RP_SIZE = 9

const OCF_LE_SET_RANDOM_ADDRESS = 0x0005

const LE_SET_RANDOM_ADDRESS_CP_SIZE = 6

const OCF_LE_SET_ADVERTISING_PARAMETERS = 0x0006

const LE_SET_ADVERTISING_PARAMETERS_CP_SIZE = 15

const OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x0007

const LE_READ_ADVERTISING_CHANNEL_TX_POWER_RP_SIZE = 2

const OCF_LE_SET_ADVERTISING_DATA = 0x0008

const LE_SET_ADVERTISING_DATA_CP_SIZE = 32

const OCF_LE_SET_SCAN_RESPONSE_DATA = 0x0009

const LE_SET_SCAN_RESPONSE_DATA_CP_SIZE = 32

const OCF_LE_SET_ADVERTISE_ENABLE = 0x000a

const LE_SET_ADVERTISE_ENABLE_CP_SIZE = 1

const OCF_LE_SET_SCAN_PARAMETERS = 0x000b

const LE_SET_SCAN_PARAMETERS_CP_SIZE = 7

const OCF_LE_SET_SCAN_ENABLE = 0x000c

const LE_SET_SCAN_ENABLE_CP_SIZE = 2

const OCF_LE_CREATE_CONN = 0x000d

const LE_CREATE_CONN_CP_SIZE = 25

const OCF_LE_CREATE_CONN_CANCEL = 0x000e

const OCF_LE_READ_WHITE_LIST_SIZE = 0x000f

const LE_READ_WHITE_LIST_SIZE_RP_SIZE = 2

const OCF_LE_CLEAR_WHITE_LIST = 0x0010

const OCF_LE_ADD_DEVICE_TO_WHITE_LIST = 0x0011

const LE_ADD_DEVICE_TO_WHITE_LIST_CP_SIZE = 7

const OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST = 0x0012

const LE_REMOVE_DEVICE_FROM_WHITE_LIST_CP_SIZE = 7

const OCF_LE_CONN_UPDATE = 0x0013

const LE_CONN_UPDATE_CP_SIZE = 14

const OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION = 0x0014

const LE_SET_HOST_CHANNEL_CLASSIFICATION_CP_SIZE = 5

const OCF_LE_READ_CHANNEL_MAP = 0x0015

const LE_READ_CHANNEL_MAP_CP_SIZE = 2

const LE_READ_CHANNEL_MAP_RP_SIZE = 8

const OCF_LE_READ_REMOTE_USED_FEATURES = 0x0016

const LE_READ_REMOTE_USED_FEATURES_CP_SIZE = 2

const OCF_LE_ENCRYPT = 0x0017

const LE_ENCRYPT_CP_SIZE = 32

const LE_ENCRYPT_RP_SIZE = 17

const OCF_LE_RAND = 0x0018

const LE_RAND_RP_SIZE = 9

const OCF_LE_START_ENCRYPTION = 0x0019

const LE_START_ENCRYPTION_CP_SIZE = 28

const OCF_LE_LTK_REPLY = 0x001a

const LE_LTK_REPLY_CP_SIZE = 18

const LE_LTK_REPLY_RP_SIZE = 3

const OCF_LE_LTK_NEG_REPLY = 0x001b

const LE_LTK_NEG_REPLY_CP_SIZE = 2

const LE_LTK_NEG_REPLY_RP_SIZE = 3

const OCF_LE_READ_SUPPORTED_STATES = 0x001c

const LE_READ_SUPPORTED_STATES_RP_SIZE = 9

const OCF_LE_RECEIVER_TEST = 0x001d

const LE_RECEIVER_TEST_CP_SIZE = 1

const OCF_LE_TRANSMITTER_TEST = 0x001e

const LE_TRANSMITTER_TEST_CP_SIZE = 3

const OCF_LE_TEST_END = 0x001f

const LE_TEST_END_RP_SIZE = 3

const OCF_LE_ADD_DEVICE_TO_RESOLV_LIST = 0x0027

const LE_ADD_DEVICE_TO_RESOLV_LIST_CP_SIZE = 39

const OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST = 0x0028

const LE_REMOVE_DEVICE_FROM_RESOLV_LIST_CP_SIZE = 7

const OCF_LE_CLEAR_RESOLV_LIST = 0x0029

const OCF_LE_READ_RESOLV_LIST_SIZE = 0x002a

const LE_READ_RESOLV_LIST_SIZE_RP_SIZE = 2

const OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE = 0x002d

const LE_SET_ADDRESS_RESOLUTION_ENABLE_CP_SIZE = 1

const OGF_VENDOR_CMD = 0x3f

const EVT_INQUIRY_COMPLETE = 0x01

const EVT_INQUIRY_RESULT = 0x02

const INQUIRY_INFO_SIZE = 14

const EVT_CONN_COMPLETE = 0x03

const EVT_CONN_COMPLETE_SIZE = 11

const EVT_CONN_REQUEST = 0x04

const EVT_CONN_REQUEST_SIZE = 10

const EVT_DISCONN_COMPLETE = 0x05

const EVT_DISCONN_COMPLETE_SIZE = 4

const EVT_AUTH_COMPLETE = 0x06

const EVT_AUTH_COMPLETE_SIZE = 3

const EVT_REMOTE_NAME_REQ_COMPLETE = 0x07

const EVT_REMOTE_NAME_REQ_COMPLETE_SIZE = 255

const EVT_ENCRYPT_CHANGE = 0x08

const EVT_ENCRYPT_CHANGE_SIZE = 4

const EVT_CHANGE_CONN_LINK_KEY_COMPLETE = 0x09

const EVT_CHANGE_CONN_LINK_KEY_COMPLETE_SIZE = 3

const EVT_MASTER_LINK_KEY_COMPLETE = 0x0a

const EVT_MASTER_LINK_KEY_COMPLETE_SIZE = 4

const EVT_READ_REMOTE_FEATURES_COMPLETE = 0x0b

const EVT_READ_REMOTE_FEATURES_COMPLETE_SIZE = 11

const EVT_READ_REMOTE_VERSION_COMPLETE = 0x0c

const EVT_READ_REMOTE_VERSION_COMPLETE_SIZE = 8

const EVT_QOS_SETUP_COMPLETE = 0x0d

const EVT_QOS_SETUP_COMPLETE_SIZE = 4 + HCI_QOS_CP_SIZE

const EVT_CMD_COMPLETE = 0x0e

const EVT_CMD_COMPLETE_SIZE = 3

const EVT_CMD_STATUS = 0x0f

const EVT_CMD_STATUS_SIZE = 4

const EVT_HARDWARE_ERROR = 0x10

const EVT_HARDWARE_ERROR_SIZE = 1

const EVT_FLUSH_OCCURRED = 0x11

const EVT_FLUSH_OCCURRED_SIZE = 2

const EVT_ROLE_CHANGE = 0x12

const EVT_ROLE_CHANGE_SIZE = 8

const EVT_NUM_COMP_PKTS = 0x13

const EVT_NUM_COMP_PKTS_SIZE = 1

const EVT_MODE_CHANGE = 0x14

const EVT_MODE_CHANGE_SIZE = 6

const EVT_RETURN_LINK_KEYS = 0x15

const EVT_RETURN_LINK_KEYS_SIZE = 1

const EVT_PIN_CODE_REQ = 0x16

const EVT_PIN_CODE_REQ_SIZE = 6

const EVT_LINK_KEY_REQ = 0x17

const EVT_LINK_KEY_REQ_SIZE = 6

const EVT_LINK_KEY_NOTIFY = 0x18

const EVT_LINK_KEY_NOTIFY_SIZE = 23

const EVT_LOOPBACK_COMMAND = 0x19

const EVT_DATA_BUFFER_OVERFLOW = 0x1a

const EVT_DATA_BUFFER_OVERFLOW_SIZE = 1

const EVT_MAX_SLOTS_CHANGE = 0x1b

const EVT_MAX_SLOTS_CHANGE_SIZE = 3

const EVT_READ_CLOCK_OFFSET_COMPLETE = 0x1c

const EVT_READ_CLOCK_OFFSET_COMPLETE_SIZE = 5

const EVT_CONN_PTYPE_CHANGED = 0x1d

const EVT_CONN_PTYPE_CHANGED_SIZE = 5

const EVT_QOS_VIOLATION = 0x1e

const EVT_QOS_VIOLATION_SIZE = 2

const EVT_PSCAN_REP_MODE_CHANGE = 0x20

const EVT_PSCAN_REP_MODE_CHANGE_SIZE = 7

const EVT_FLOW_SPEC_COMPLETE = 0x21

const EVT_FLOW_SPEC_COMPLETE_SIZE = 5 + HCI_QOS_CP_SIZE

const EVT_INQUIRY_RESULT_WITH_RSSI = 0x22

const INQUIRY_INFO_WITH_RSSI_SIZE = 14

const INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE = 15

const EVT_READ_REMOTE_EXT_FEATURES_COMPLETE = 0x23

const EVT_READ_REMOTE_EXT_FEATURES_COMPLETE_SIZE = 13

const EVT_SYNC_CONN_COMPLETE = 0x2c

const EVT_SYNC_CONN_COMPLETE_SIZE = 17

const EVT_SYNC_CONN_CHANGED = 0x2d

const EVT_SYNC_CONN_CHANGED_SIZE = 9

const EVT_SNIFF_SUBRATING = 0x2e

const EVT_SNIFF_SUBRATING_SIZE = 11

const EVT_EXTENDED_INQUIRY_RESULT = 0x2f

const EXTENDED_INQUIRY_INFO_SIZE = 254

const EVT_ENCRYPTION_KEY_REFRESH_COMPLETE = 0x30

const EVT_ENCRYPTION_KEY_REFRESH_COMPLETE_SIZE = 3

const EVT_IO_CAPABILITY_REQUEST = 0x31

const EVT_IO_CAPABILITY_REQUEST_SIZE = 6

const EVT_IO_CAPABILITY_RESPONSE = 0x32

const EVT_IO_CAPABILITY_RESPONSE_SIZE = 9

const EVT_USER_CONFIRM_REQUEST = 0x33

const EVT_USER_CONFIRM_REQUEST_SIZE = 10

const EVT_USER_PASSKEY_REQUEST = 0x34

const EVT_USER_PASSKEY_REQUEST_SIZE = 6

const EVT_REMOTE_OOB_DATA_REQUEST = 0x35

const EVT_REMOTE_OOB_DATA_REQUEST_SIZE = 6

const EVT_SIMPLE_PAIRING_COMPLETE = 0x36

const EVT_SIMPLE_PAIRING_COMPLETE_SIZE = 7

const EVT_LINK_SUPERVISION_TIMEOUT_CHANGED = 0x38

const EVT_LINK_SUPERVISION_TIMEOUT_CHANGED_SIZE = 4

const EVT_ENHANCED_FLUSH_COMPLETE = 0x39

const EVT_ENHANCED_FLUSH_COMPLETE_SIZE = 2

const EVT_USER_PASSKEY_NOTIFY = 0x3b

const EVT_USER_PASSKEY_NOTIFY_SIZE = 10

const EVT_KEYPRESS_NOTIFY = 0x3c

const EVT_KEYPRESS_NOTIFY_SIZE = 7

const EVT_REMOTE_HOST_FEATURES_NOTIFY = 0x3d

const EVT_REMOTE_HOST_FEATURES_NOTIFY_SIZE = 14

const EVT_LE_META_EVENT = 0x3e

const EVT_LE_META_EVENT_SIZE = 1

const EVT_LE_CONN_COMPLETE = 0x01

const EVT_LE_CONN_COMPLETE_SIZE = 18

const EVT_LE_ADVERTISING_REPORT = 0x02

const LE_ADVERTISING_INFO_SIZE = 9

const EVT_LE_CONN_UPDATE_COMPLETE = 0x03

const EVT_LE_CONN_UPDATE_COMPLETE_SIZE = 9

const EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04

const EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE_SIZE = 11

const EVT_LE_LTK_REQUEST = 0x05

const EVT_LE_LTK_REQUEST_SIZE = 12

const EVT_PHYSICAL_LINK_COMPLETE = 0x40

const EVT_PHYSICAL_LINK_COMPLETE_SIZE = 2

const EVT_CHANNEL_SELECTED = 0x41

const EVT_DISCONNECT_PHYSICAL_LINK_COMPLETE = 0x42

const EVT_DISCONNECT_PHYSICAL_LINK_COMPLETE_SIZE = 3

const EVT_PHYSICAL_LINK_LOSS_EARLY_WARNING = 0x43

const EVT_PHYSICAL_LINK_LOSS_WARNING_SIZE = 2

const EVT_PHYSICAL_LINK_RECOVERY = 0x44

const EVT_PHYSICAL_LINK_RECOVERY_SIZE = 1

const EVT_LOGICAL_LINK_COMPLETE = 0x45

const EVT_LOGICAL_LINK_COMPLETE_SIZE = 5

const EVT_DISCONNECT_LOGICAL_LINK_COMPLETE = 0x46

const EVT_FLOW_SPEC_MODIFY_COMPLETE = 0x47

const EVT_FLOW_SPEC_MODIFY_COMPLETE_SIZE = 3

const EVT_NUMBER_COMPLETED_BLOCKS = 0x48

const EVT_AMP_STATUS_CHANGE = 0x4d

const EVT_AMP_STATUS_CHANGE_SIZE = 2

const EVT_TESTING = 0xfe

const EVT_VENDOR = 0xff

const EVT_STACK_INTERNAL = 0xfd

const EVT_STACK_INTERNAL_SIZE = 2

const EVT_SI_DEVICE = 0x01

const EVT_SI_DEVICE_SIZE = 4

const HCI_TYPE_LEN = 1

const HCI_COMMAND_HDR_SIZE = 3

const HCI_EVENT_HDR_SIZE = 2

const HCI_ACL_HDR_SIZE = 4

const HCI_SCO_HDR_SIZE = 3

const HCI_MSG_HDR_SIZE = 6

const HCI_DATA_DIR = 1

const HCI_FILTER = 2

const HCI_TIME_STAMP = 3

const HCI_CMSG_DIR = 0x0001

const HCI_CMSG_TSTAMP = 0x0002

const HCI_DEV_NONE = 0xffff

const HCI_CHANNEL_RAW = 0

const HCI_CHANNEL_USER = 1

const HCI_CHANNEL_MONITOR = 2

const HCI_CHANNEL_CONTROL = 3

const HCI_CHANNEL_LOGGING = 4

const HCI_FLT_TYPE_BITS = 31

const HCI_FLT_EVENT_BITS = 63

const HCI_FLT_OGF_BITS = 63

const HCI_FLT_OCF_BITS = 127

const IREQ_CACHE_FLUSH = 0x0001

const SDP_RECORD_PERSIST = 0x01

const SDP_DEVICE_RECORD = 0x02

const SDP_RETRY_IF_BUSY = 0x01

const SDP_WAIT_ON_CLOSE = 0x02

const SDP_NON_BLOCKING = 0x04

const SDP_LARGE_MTU = 0x08

const MAX_LEN_UUID_STR = 37

const MAX_LEN_PROTOCOL_UUID_STR = 8

const MAX_LEN_SERVICECLASS_UUID_STR = 28

const MAX_LEN_PROFILEDESCRIPTOR_UUID_STR = 28

end # module
