import sys

import time

from spotify_credentials import get_credentials, invalidate_credentials

if sys.implementation.name == 'micropython':
    import urequests as requests
    import machine
else:
    import requests


def play_seagulls(credentials):
    play_endpoint = "https://api.spotify.com/v1/me/player/play"
    url = "{path}?device_id={device_id}".format(path=play_endpoint, device_id=credentials['device_id'])
    requests.put(
        url,
        headers={'Authorization': "Bearer {access_token}".format(**credentials)},
        json={"uris": ["spotify:track:471sXvN5C5vfMSBdKrGpo7"]},
    )


def stop(credentials):
    stop_endpoint = "https://api.spotify.com/v1/me/player/pause"
    url = "{path}?device_id={device_id}".format(path=stop_endpoint, device_id=credentials['device_id'])
    requests.put(
        url,
        headers={'Authorization': "Bearer {access_token}".format(**credentials)},
    )


def run(button):
    print("Running")
    while True:
        if not button.value():
            time.sleep(0.3)
            if button.value():
                print("Seagulls! Stop it now!")
                credentials = get_credentials()
                play_seagulls(credentials)
            else:
                print("Stop!")
                credentials = get_credentials()
                stop(credentials)
            while not button.value():
                time.sleep(0.1)
        time.sleep(0.01)


def check_reset_settings(button):
    if not button.value():
        time.sleep(7)
        if not button.value():
            print("Invalidating credentials")
            invalidate_credentials()
            get_credentials()
            while not button.value():
                time.sleep(0.1)


def main():
    print("\033c")
    button = machine.Pin(12, machine.Pin.IN, machine.Pin.PULL_UP)
    check_reset_settings(button)
    run(button)


if __name__ == '__main__':
    main()
