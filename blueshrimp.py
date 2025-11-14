import asyncio

import bumble.logging
from bumble import core, hci, rfcomm, transport, utils, hfp, sdp
from bumble.colors import color
from bumble.device import Connection, Device, DeviceConfiguration

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


async def main():
    bumble.logging.setup_basic_logging("INFO")
    async with await transport.open_transport(hci_transport) as (
            hci_source,
            hci_sink,
    ):
        device = Device.from_config_file_with_hci(device_config, hci_source,
                                                  hci_sink)
        device.classic_enabled = True
        channel = 3
        configuration = _default_configuration()
        device.sdp_service_records = {
            1: hfp.make_ag_sdp_records(1, channel, configuration)
        }
        print(device.sdp_server.on_sdp_service_search_attribute_request)
        requests = []

        def my_hook(request_):
            print("got SDP, doing NOTHING", request_)
            requests.append(request_)

        device.sdp_server.orig_on_sdp_service_search_attribute_request = device.sdp_server.on_sdp_service_search_attribute_request
        device.sdp_server.on_sdp_service_search_attribute_request = my_hook

        await device.power_on()
        connection = await device.connect(
            address, transport=core.PhysicalTransport.BR_EDR)
        await connection.encrypt()
        rfcomm_client = rfcomm.Client(connection)
        rfcomm_mux = await rfcomm_client.start()
        channel = await rfcomm_mux.open_dlc(4)
        print("open dlc!!!!!!!")
        await asyncio.sleep(0.5)
        await channel.disconnect()
        await asyncio.sleep(0.5)
        channel = await rfcomm_mux.open_dlc(4)
        await asyncio.sleep(0.5)
        device.sdp_server.send_response(
            sdp.SDP_ErrorResponse(
                transaction_id=requests[0].transaction_id,
                error_code=sdp.SDP_INVALID_SERVICE_RECORD_HANDLE_ERROR,
            ))
        await asyncio.sleep(0.5)
        device.sdp_server.orig_on_sdp_service_search_attribute_request(
            requests[1])
        await asyncio.sleep(4)


asyncio.run(main())
