import asyncio

import bumble.logging
from bumble import core, hci, rfcomm, transport, utils, hfp, sdp
from bumble.colors import color
from bumble.device import Connection, Device, DeviceConfiguration

hci_transport = "android-netsim"
device_config = "device.json"
address = "DA:4C:10:DE:17:00"

# copied from Bumble's examples/run_hfp_gateway.py

async def main():
    bumble.logging.setup_basic_logging("INFO")
    async with await transport.open_transport(hci_transport) as (
            hci_source,
            hci_sink,
    ):
        device = Device.from_config_file_with_hci(device_config, hci_source,
                                                  hci_sink)
        device.classic_enabled = True
        #channel = 3
        #configuration = _default_configuration()
        #device.sdp_service_records = {
        #    1: hfp.make_ag_sdp_records(1, channel, configuration)
        #}
        print(device.sdp_server.on_sdp_service_search_attribute_request)
        requests = []

        def my_hook(request_):
            print("got SDP, doing NOTHING", request_)
            requests.append(request_)

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
        channel = await rfcomm_mux.open_dlc(4)
        #await channel.disconnect()
        await asyncio.sleep(0.5)
        device.sdp_server.send_response(
            sdp.SDP_ErrorResponse(
                transaction_id=requests[0].transaction_id,
                error_code=sdp.SDP_INVALID_SERVICE_RECORD_HANDLE_ERROR,
            ))
        await asyncio.sleep(4)


asyncio.run(main())
