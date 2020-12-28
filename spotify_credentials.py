import sys

if sys.implementation.name == 'micropython':
    # noinspection PyUnresolvedReferences
    import usocket as socket
    # noinspection PyUnresolvedReferences
    import urequests as requests
    # noinspection PyUnresolvedReferences
    import ujson as json

    class JSONDecodeError(Exception):
        pass

    # noinspection PyShadowingBuiltins
    class FileNotFoundError(Exception):
        pass
else:
    import socket
    import requests
    import json
    from json import JSONDecodeError


INITIAL_RESPONSE_TEMPLATE = """\
HTTP/1.0 200 OK
Content-Type: text/html

<h1>Authenticate with Spotify</h1>
1) Go to <a target="_blank" href="https://developer.spotify.com/dashboard/applications">Spotify for Developers</a> and "Create an app"<br>
2) Edit Settings on the app, add "{redirect_uri}" as a Redirect URI and Save<br>
3) Enter Client ID below, submit and then allow the scopes for the app.<br><br>

<form action="/auth-request" method="post">
    client_id: <input type="text" name="client_id" size="34" value="{default_client_id}"><br><br>
    client_secret: <input type="text" name="client_secret" size="34" value="{default_client_secret}"><br><br>
    <input type="submit" value="Submit">
</form>
"""


SELECT_DEVICE_TEMPLATE = """\
HTTP/1.0 200 OK
Content-Type: text/html

<h1>Select device</h1>

<form action="/select-device" method="post">
    {device_list}
    <input type="submit" value="Submit">
</form>
"""


AUTH_REDIRECT_TEMPLATE = """\
HTTP/1.0 302 Found
Location: {url}
"""

NOT_FOUND = """\
HTTP/1.0 404 NOT FOUND

"""

DONE_RESPONSE = """\
HTTP/1.0 200 OK
Content-Type: text/html

OK
"""


def setup_authorization_code_flow(default_client_id='', default_client_secret='', default_device_id=''):
    micropython_optimize = sys.implementation.name == 'micropython'
    s = socket.socket()

    # Binding to all interfaces - server will be accessible to other hosts!
    ai = socket.getaddrinfo("0.0.0.0", 8080)
    addr = ai[0][-1]

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr)
    s.listen(5)
    print("Listening, connect your browser to http://{myip}:8080/".format(myip=myip()))

    redirect_uri = None
    client_id = None
    client_secret = None
    credentials = None
    device_selected = False

    while not device_selected:
        client_sock, _ = s.accept()

        if micropython_optimize:
            client_stream = client_sock
        else:
            client_stream = client_sock.makefile("rwb")

        req = client_stream.readline().decode()
        content_length = None

        while True:
            h = client_stream.readline().decode()
            if h.startswith("Host: "):
                host = h[6:-2]
                redirect_uri = 'http://{host}/auth-response/'.format(host=host)
            if h.startswith("Content-Length: "):
                content_length = int(h[16:-2])
            if h == "" or h == "\r\n":
                break

        def write_response(resp):
            client_stream.write(resp.encode())
            client_stream.close()
            if not micropython_optimize:
                client_sock.close()

        if req.startswith("GET / "):
            write_response(INITIAL_RESPONSE_TEMPLATE.format(
                redirect_uri=redirect_uri,
                default_client_id=default_client_id,
                default_client_secret=default_client_secret,
            ))

        elif req.startswith("POST /auth-request"):
            authorization_endpoint = 'https://accounts.spotify.com/authorize'
            form_values = parse_qs(client_stream.read(content_length).decode())
            client_id = form_values['client_id'][0]
            client_secret = form_values['client_secret'][0]
            params = dict(
                client_id=client_id,
                response_type='code',
                redirect_uri=redirect_uri,
                scope='user-read-playback-state user-modify-playback-state',
            )
            url = "{path}?{query}".format(path=authorization_endpoint, query=urlencode(params))
            write_response(AUTH_REDIRECT_TEMPLATE.format(url=url))

        elif req.startswith("GET /auth-response"):
            authorization_code = parse_qs(req[4:-11].split('?')[1])['code'][0]
            credentials = get_access_tokens(authorization_code, redirect_uri, client_id, client_secret)
            device_list = get_available_devices(credentials)
            device_list_html = []
            for device in device_list:
                checked = 'checked' if device['id'] == default_device_id else ''
                device_list_html.append("""<input type="radio" name="device_id" value="{id}" {checked}> {name}<br>""".format(checked=checked, **device))
            write_response(SELECT_DEVICE_TEMPLATE.format(device_list=''.join(device_list_html)))

        elif req.startswith("POST /select-device"):
            device_selected = True
            response = client_stream.read(content_length).decode()
            credentials['device_id'] = parse_qs(response)['device_id'][0]
            write_response(DONE_RESPONSE)

        else:
            write_response(NOT_FOUND)

    return credentials


def get_access_tokens(authorization_code, redirect_uri, client_id, client_secret):
    params = dict(
        grant_type="authorization_code",
        code=authorization_code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
    )

    access_token_endpoint = "https://accounts.spotify.com/api/token"
    response = requests.post(
        access_token_endpoint,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data=urlencode(params),
    )
    tokens = response.json()
    return dict(
        access_token=tokens['access_token'],
        refresh_token=tokens['refresh_token'],
        client_id=client_id,
        client_secret=client_secret,
    )


def get_available_devices(credentials):
    devices_endpoint = "https://api.spotify.com/v1/me/player/devices"
    return requests.get(
        devices_endpoint,
        headers={'Authorization': "Bearer {access_token}".format(**credentials)},
    ).json()['devices']


def refresh_access_token(credentials):
    access_token_endpoint = "https://accounts.spotify.com/api/token"
    params = dict(
        grant_type="refresh_token",
        refresh_token=credentials['refresh_token'],
        client_id=credentials['client_id'],
        client_secret=credentials['client_secret'],
    )
    response = requests.post(
        access_token_endpoint,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data=urlencode(params),
    )
    if response.status_code != 200:
        raise RefreshAccessTokenError
    tokens = response.json()
    credentials['access_token'] = tokens['access_token']
    if 'refresh_token' in tokens:
        credentials['refresh_token'] = tokens['refresh_token']
        store_credentials(credentials)


class RefreshAccessTokenError(Exception):
    pass


def get_credentials(setup=False):
    credentials = load_credentials()

    if credentials:
        if not setup:
            try:
                refresh_access_token(credentials)
            except RefreshAccessTokenError:
                setup = True
            if credentials.get('invalide') == 'true':
                setup = True
        if setup:
            credentials = setup_authorization_code_flow(
                default_client_id=credentials['client_id'],
                default_client_secret=credentials['client_secret'],
                default_device_id=credentials['device_id'],
            )
            store_credentials(credentials)

    else:
        credentials = setup_authorization_code_flow()
        store_credentials(credentials)

    return credentials


def load_credentials():
    try:
        with open('credentials.json') as credentials_file:
            credentials = json.loads(credentials_file.read())
        assert credentials['refresh_token']
        assert credentials['client_id']
        assert credentials['client_secret']
        assert credentials['device_id']
    except (OSError, ValueError, FileNotFoundError, JSONDecodeError, KeyError, AssertionError):
        credentials = None
    return credentials


def store_credentials(credentials):
    with open('credentials.json', 'w') as credentials_file:
        credentials_file.write(json.dumps(credentials))


def invalidate_credentials():
    credentials = load_credentials()
    if credentials is not None:
        credentials['invalide'] = 'true'
    store_credentials(credentials)


def myip():
    if sys.implementation.name == 'micropython':
        try:
            import network
            return network.WLAN(network.STA_IF).ifconfig()[0]
        except ImportError:
            return "<my host>"
    else:
        return (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]


def parse_qs(qs):
    parsed_result = {}
    pairs = parse_qsl(qs)
    for name, value in pairs:
        if name in parsed_result:
            parsed_result[name].append(value)
        else:
            parsed_result[name] = [value]
    return parsed_result


def parse_qsl(qs):
    pairs = [s2 for s1 in qs.split('&') for s2 in s1.split(';')]
    r = []
    for name_value in pairs:
        if not name_value:
            continue
        nv = name_value.split('=', 1)
        if len(nv) != 2:
            continue
        if len(nv[1]):
            name = nv[0].replace('+', ' ')
            name = unquote(name)
            value = nv[1].replace('+', ' ')
            value = unquote(value)
            r.append((name, value))
    return r


def quote(s):
    always_safe = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                   'abcdefghijklmnopqrstuvwxyz'
                   '0123456789' '_.-')
    res = []
    for c in s:
        if c in always_safe:
            res.append(c)
            continue
        res.append('%%%x' % ord(c))
    return ''.join(res)


def quote_plus(s):
    s = quote(s)
    if ' ' in s:
        s = s.replace(' ', '+')
    return s


def unquote(s):
    res = s.split('%')
    for i in range(1, len(res)):
        item = res[i]
        try:
            res[i] = chr(int(item[:2], 16)) + item[2:]
        except ValueError:
            res[i] = '%' + item
    return "".join(res)


def unquote_plus(s):
    s = s.replace('+', ' ')
    return unquote(s)


def urlencode(query):
    if isinstance(query, dict):
        query = query.items()
    li = []
    for k, v in query:
        if not isinstance(v, list):
            v = [v]
        for value in v:
            k = quote_plus(str(k))
            v = quote_plus(str(value))
            li.append(k + '=' + v)
    return '&'.join(li)
