"""
Campus network login script designed for the srun portal in Beijing Institute of Technology (after Nov. 2021)
"""
import argparse
import base64
import ctypes
import datetime
import getpass
import hashlib
import hmac
import json
import math
import sys
import time
import urllib
import urllib.parse
import urllib.request


def urs(a, n):
    """
    unsigned right shift (>>> in javascript)
    :param a:
    :return:
    """
    if a >= 0:
        return a >> n
    else:
        return (a + 0x100000000) >> n


def int32(a):
    """
    convert to 32-bit integer
    :param a:
    :return:
    """
    return int(ctypes.c_int32(a).value)


# custom alphabet for base64 encoding
# bower/all/1.0.0/all.min.js  line 16 (modified version of jquery-base64)
_std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_custom_alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
def b64_encode_custom(b):
    x = base64.b64encode(b)
    return bytes(str(x)[2:-1].translate(str(x)[2:-1].maketrans(_std_alpha, _custom_alpha)), 'utf-8')


def _http_get(base, path, data):
    # # requests
    # url = urllib.parse.urljoin(base, path)
    # response = requests.get(url, params=data, headers={
    #     "content-type": "application/json; charset=utf-8",
    #     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    # })
    # return response.content.decode('utf-8')

    # urllib
    params = urllib.parse.urlencode(data)
    url = urllib.parse.urljoin(base, path + '?' + params)     # GET request
    request = urllib.request.Request(url, headers={
        "content-type": "application/json; charset=utf-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    })
    response = urllib.request.urlopen(request)
    return response.read().decode('utf-8')


def getChallenge(url, data):
    """
    /static/js/jquery.srun.portal.js#87
    :param url: "http://10.0.0.55/cgi-bin/get_challenge"
    :param data: ...
    :return:
    """
    return _http_get(url, '/cgi-bin/get_challenge', data)



def srunPortal(url, data):
    """
    function srunPortal(url, data, callback) {
        return $.get(url + "/cgi-bin/srun_portal", data, callback, "jsonp");
    }
    /static/js/jquery.srun.portal.js#110
    :param url:
    :param data:
    :return:
    """
    return _http_get(url, '/cgi-bin/srun_portal', data)



def pwd(d, k):
    """
    #99
    pwd(d, k) {
        return md5(d, k);       # hmac md5
    }
    :param d:
    :param k:
    :return:
    """
    if isinstance(k, str):
        k = bytes(k, encoding='utf-8')
    if isinstance(d, str):
        d = bytes(d, encoding='utf-8')
    # return hmac.new(key=k, msg=d).hexdigest()
    return hmac.new(key=k, msg=d, digestmod='MD5').hexdigest()


def chksum(d):
    """
    #103
    function chksum(d) {
        return sha1(d);
    }
    :param d:
    :return:
    """
    if isinstance(d, str):
        d = bytes(d, 'utf-8')
    sha1 = hashlib.sha1()
    sha1.update(d)
    return sha1.hexdigest()


def s(a, b):
    """
    function s(a, b) {
        var c = a.length, v = [];
        for (var i = 0; i < c; i += 4) {
            v[i >> 2] = a.charCodeAt(i) | a.charCodeAt(i + 1) << 8 | a.charCodeAt(i + 2) << 16 | a.charCodeAt(i + 3) << 24;
        }
        if (b) {
            v[v.length] = c;
        }
        return v;
    }
    :param a:
    :param b:
    :return:
    """
    c = len(a)
    v = []
    while len(a) % 4 != 0:      # padding to avoid IndexError
        a += chr(0)
    for i in range(0, c, 4):
        v.append(ord(a[i]) | (ord(a[i + 1]) << 8) | (ord(a[i + 2]) << 16) | (ord(a[i + 3]) << 24))
    if b:
        v.append(c)
    return v


def l(a, b):
    """
    function l(a, b) {
        var d = a.length, c = (d - 1) << 2;
        if (b) {
            var m = a[d - 1];
            if ((m < c - 3) || (m > c))
                return null;
            c = m;
        }
        for (var i = 0; i < d; i++) {
            a[i] = String.fromCharCode(a[i] & 0xff, a[i] >>> 8 & 0xff, a[i] >>> 16 & 0xff, a[i] >>> 24 & 0xff);
        }
        if (b) {
            return a.join('').substring(0, c);
        } else {
            return a.join('');
        }
    }
    """
    if isinstance(a, str):
        a = [ord(_) for _ in a]
    _a = [None for _ in a]
    d = len(a)
    c = (d - 1) << 2
    if b:
        m = a[d - 1]
        if (m < c - 3) or (m > c):
            return None;
        c = m;
    for i in range(d):
        # print('a[' + str(i) + ']:', a[i], a[i] & 0xff, urs(a[i], 8) & 0xff, urs(a[i], 16) & 0xff, urs(a[i], 24) & 0xff)
        _a[i] = [a[i] & 0xff, urs(a[i], 8) & 0xff, urs(a[i], 16) & 0xff, urs(a[i], 24) & 0xff]
        # print('a[' + str(i) + ']:', _a[i])
    __a = []
    for _ in _a: __a.extend(_)
    _a = __a

    if b:
        return bytes(_a[:c])
    else:
        return bytes(_a)


def xEncode(str, key):
    """
    /static/js/jquery.srun.portal.js#21
    function xEncode(str, key) {
        if (str == "") {
            return "";
        }
        var v = s(str, true),
            k = s(key, false);
        if (k.length < 4) {
            k.length = 4;
        }
        var n = v.length - 1,
            z = v[n],
            y = v[0],
            c = 0x86014019 | 0x183639A0,
            m,
            e,
            p,
            q = Math.floor(6 + 52 / (n + 1)),
            d = 0;
        while (0 < q--) {
            d = d + c & (0x8CE0D9BF | 0x731F2640);
            e = d >>> 2 & 3;
            for (p = 0; p < n; p++) {
                y = v[p + 1];
                m = z >>> 5 ^ y << 2;
                m += (y >>> 3 ^ z << 4) ^ (d ^ y);
                m += k[(p & 3) ^ e] ^ z;
                z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF);
            }
            y = v[0];
            m = z >>> 5 ^ y << 2;
            m += (y >>> 3 ^ z << 4) ^ (d ^ y);
            m += k[(p & 3) ^ e] ^ z;
            z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD);
        }
        return l(v, false);
    }
    :param d:
    :param k:
    :return:
    """
    if len(str) == 0:
        return ""
    v = s(str, True)
    k = s(key, False)
    if len(k) < 4:
        while len(k) < 4:
            k.append(0)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = int32(0x86014019 | 0x183639A0)         # 0x9E3C0D99
    m = None
    e = None
    p = None
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        q -= 1
        d = int32(int32(d) + int32(c & int32(0x8CE0D9BF | 0x731F2640)))
        e = int32(urs(d, 2) & 3)

        for p in range(n):
            y = int32(v[p + 1])
            m = int32(urs(z, 5)) ^ int32(y << 2)
            # print('\t', 'm:', m, 'z >>> 5:', urs(z, 5))
            m = m + (int32(urs(y, 3) ^ int32(z << 4)) ^ int32(d ^ y))
            # print('\t', 'm:', m, 'y >>> 3:', int64(urs(y, 3) ^ int64(z << 4)) ^ int64(d ^ y))
            m = m + (int32(k[(p & 3) ^ e]) ^ z)
            # print('\t', 'm:', m, 'a:', int64(k[(p & 3) ^ e]), z)
            z = v[p] = int32(int32(v[p]) + int32(m & (0xEFB8D130 | 0x10472ECF)))
            # print('\t', 'p:', p, 'y:', y, 'm:', m, 'z:', z)
        p += 1

        y = v[0]
        m = int32(urs(z, 5)) ^ int32(y << 2)
        # print('p:', p)
        # print('1 m:', m, (int64(urs(y, 3) ^ int64(z << 4)) ^ int64(d ^ y)))
        m = m + (int32(urs(y, 3) ^ int32(z << 4)) ^ int32(d ^ y))
        # print('2 m:', m, (p & 3), e, int64(z))
        m = m + (int32(k[(p & 3) ^ e]) ^ int32(z))
        # print('3 m:', m, 'n:', n)
        z = v[n] = int32(int32(v[n]) + int32(m & (0xBB390742 | 0x44C6F8BD)))
        # print('v[n]:', v[n])
    ret = l(v, False)
    return ret


def info(d, k):
    """
    /static/js/jquery.srun.portal.js#95
    function info(d, k) {
        return "{SRBX1}" + $.base64.encode(xEncode(json(d), k));
    }
    :param d:
    :param k:
    :return:
    """
    tmp = xEncode(json.dumps(d).replace(' ', ''), k)
    # tmp_i = [int(_) for _ in tmp]
    ret = b"{SRBX1}" + b64_encode_custom(tmp)
    return ret.decode(encoding='utf-8')


def login(username, password):
    n = 200
    type = 1

    url = "http://10.0.0.55/"

    data = {
        "username": username,
        "domain": "",               # empty string
        "password": password,
        "ac_id": "1",
        "ip": "",                   # can be empty string
        "double_stack": 0,
        "otp": False,               # can be false, depend on the webpage form
        "ignore": 2
    }

    # get challenge
    params = {
        'username': data['username'],
        'ip': data['ip'],
    }
    response = getChallenge(url, params)
    response = json.loads(response)
    print('>>> get_challenge:', response)

    # srun portal
    username = data['username'] + (data['domain'] or "")
    token = response['challenge']
    i = info({
            "username": username,   # username
            "password": data['password'],   # data.password
            "ip": data['ip'] or response['client_ip'],               # (data.ip || response.client_ip)
            "acid": data['ac_id'],                    # data.ac_id
            "enc_ver": "srun_bx1"
        }, token)
    hmd5 = pwd(data['password'], token)
    # print('info:', i)

    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + data['ac_id']
    chkstr += token + (data['ip'] or response['client_ip'])
    chkstr += token + str(n)
    chkstr += token + str(type)
    chkstr += token + i
    os = "Windows 10"      # TODO: get value from user agent

    if data['otp']:
        data['password'] = "{OTP}" + data['password']
    else:
        data['password'] = "{MD5}" + hmd5
    params = {
        'callback': 'jQuery1124005377181060614311_1637943230104',       # could be anything
        'action': "login",
        'username': username,
        'password': data['password'],
        'ac_id': data['ac_id'],
        'ip': data['ip'] or response['client_ip'],
        'chksum': chksum(chkstr),
        'info': i,
        'n': n,
        'type': type,
        'os': "Windows 10",                 # from user agent
        'name': "Windows",                  # from user agent
        'double_stack': data['double_stack'],
        'ignore': data['ignore'],
        'cas_account': None,
        'cas_password': None,
    }
    response = srunPortal(url, params)

    response = response.replace(params['callback'], '')
    if response[0] == '(' and response[-1] == ')':
        response = response[1:-1]
    resp = json.loads(response)
    print('>>> srun_portal:', resp)

    def callback(error, message):
        print('login {} | message: {}'.format(error, message))

    def process_resp(resp):
        if resp['error'] == 'ok':
            ploy_msg = ''
            if resp.get('ploy_msg', None) is not None:
                ploy_msg = resp['ploy_msg']
            if resp.get('suc_msg', None) is not None:
                if resp['suc_msg'] == 'ip_already_online_error':
                    return callback('error', resp.get('suc_msg', None))
            # success
            # print('welcome,', resp['real_name'])
            return callback('ok', ploy_msg)
        else:
            message = ','.join([str(resp.get(key, None)) for key in ['ecode', 'error', 'error_msg']])
            if resp.get('ploy_msg', None) is not None:
                message = resp.ploy_msg
            return callback('fail', message)

    process_resp(resp)


def logout(username):
    url = "http://10.0.0.55/"

    data = {
        "username": username,
        "ac_id": "1",
        "ip": "",               # can be empty string
        "domain": ""
    }
    username = (data["username"] or "") + (data["domain"] or "")
    params = {
        "username": username,
        "action": "logout",
        "ac_id": data["ac_id"],
        "ip": data["ip"] or ""
    }
    response = srunPortal(url, params)
    resp = json.loads(response)

    def callback(error, message):
        print('logout {} | message: {}'.format(error, message))

    if resp['error'] == 'ok':
        callback('ok', '')
    else:
        message = ','.join([str(resp.get(key, None)) for key in ['ecode', 'error', 'error_msg']])
        callback('fail', message)


if __name__ == '__main__':
    usage = """
    {} [option] [username] <password> <-interval INTERVAL>
        option = "auto"   => automatically login by an interval; requires username and password
        option = "login"  => single time login; requires username and password
        option = "logout" => single time logout""".format(sys.argv[0])
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('option', type=str, choices=['auto', 'login', 'logout'])
    parser.add_argument('username', type=str)
    parser.add_argument('password', type=str, nargs='?', help='optional in command line')
    parser.add_argument('-interval', type=int, default=600, help='time interval in seconds')
    args = parser.parse_args()

    option, username, password, interval = args.option, args.username, args.password, args.interval
    if len(username) == 0:
        print('please input correct username')
        sys.exit(0)
    if option in ('auto', 'login') and (password is None or len(password) == 0):
        password = getpass.getpass('please input password for user {} :'.format(username))

    if option == 'auto':
        while True:
            print(datetime.datetime.now())
            login(username, password)
            time.sleep(interval)
    elif option == 'login':
        login(username, password)
    elif option == 'logout':
        logout(username)