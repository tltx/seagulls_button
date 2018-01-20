# Seagulls button
Play SEAGULLS! (Stop It Now) on Spotify with a dedicated IOT button.

This is a Micropython project for the ESP8266 to remotely control devices with Spotify Connect, and in this case play a song. It implements a web based setup for OAuth authentication with Spotifys WebAPI, storing of credentials and refreshing of access tokens. The spotify_credentials module uses too much RAM to run as pure Python and needs to be frozen in the firmware (spotify_credentials_micropython.bin). The project should be easy to modify to do other things with the Spotify WebAPI.
