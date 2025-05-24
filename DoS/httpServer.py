import string, random, time, socket, threading, hashlib, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

#=====================================Defenses Flags======================================#
USE_RATE_LIMIT = True #enforce IP rate limiting
USE_CAPTCHA = True #enforce CAPTCHA
USE_POW = True #enforce Proof-of-Work challenge
#=========================================================================================#

#===================================Default Parameters====================================#
SERVER_IP = '127.0.0.1' #represents HTTP server IP
SERVER_PORT = 8090 #represents HTTP server port
MAX_CONNECTIONS = 50 #represents max connection handlers for HTTP server
MAX_QUEUE_SIZE = 20 #represents number of connections allowed in HTTP server queue
MAX_REQUESTS = 10 #represents max requests for rate limiting
SOCKET_TIMEOUT = 30 #represents timeout for connection socket
WINDOW_TIMEOUT = 60 #represents window timeout for rate limiting
POW_DIFFICULTY = 24 #represents number of leading zero bits required for PoW challenge
POW_TIMEOUT = 120 #represents timeout for PoW challenge
#=========================================================================================#

#====================================HTML Templates=======================================#
PROTECTED_PAGE = '''
    <!doctype html>
    <html lang=\"en\"> 
    <head>
    <meta charset=\"UTF-8\">
    <title>Protected Page</title>
    <style>
        html, body {{ height: 100%; margin: 0; }}
        body {{ display: flex; justify-content: center; align-items: center; background: #f4f4f4; font-family: Arial, sans-serif; }}
        .container {{ background: #fff; padding: 20px; border-radius: 8px; width: 360px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        label {{ display: block; margin-top: 10px; text-decoration: underline; }}
        input {{ width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 10px; margin-top: 10px; background: #28a745; color: #fff; border: none; cursor: pointer; border-radius: 4px; }}
        .error {{ color: #c00; font-size: 0.9em; margin-top: 5px; text-align: center; }}
        .success {{ color: #080; font-size: 1.1em; text-align: center; margin-bottom: 10px; }}
        .pow-note {{ font-size: 0.9em; margin-top: 10px; color: #555; text-align: center; }}
        .section {{ margin-bottom: 20px; }}
    </style>
    </head>
    <body>
    <div class=\"container\">
        <h1 style=\"text-align:center; margin-bottom: 30px;\">Protected Page</h1>
        <form action=\"/\" method=\"get\">
            <div class=\"section\">
                {captcha_section}
            </div>
            <div class=\"section\">
                {pow_section}
            </div>
            <div class=\"section\">
                {error_message}
            </div>
            <div class=\"section\">
                <button type=\"submit\">Submit</button>
            </div>
        </form>
    </div>
    </body>
    </html>
'''

SUCCESS_PAGE = '''
    <!doctype html>
    <html lang=\"en\">  
    <head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Access Granted</title>
    <style>
        body { margin: 0; font-family: Arial, sans-serif; background: linear-gradient(135deg, #81C784, #66BB6A); height: 100vh; display: flex; justify-content: center; align-items: center; }
        .message-box { background: rgba(255,255,255,0.9); padding: 40px; border-radius: 12px; text-align: center; box-shadow: 0 6px 20px rgba(0,0,0,0.1); max-width: 400px; }
        h1 { font-size: 32px; margin-bottom: 20px; color: #2E7D32; }
        p  { font-size: 18px; color: #555; }
        a.button {{ display: inline-block; margin-top: 30px; padding: 12px 24px; background: #2E7D32; color: #fff; text-decoration: none; border-radius: 6px; font-size: 16px; }
        a.button:hover { background: #27632a; }
    </style>
    </head>
    <body>
    <div class=\"message-box\">
        <h1>Access Granted!</h1>
        <p>Congratulations, you have successfully passed all security checks.</p>
        <a href=\"/protected\" class=\"button\">Go Back</a>
    </div>
    </body>
    </html>
'''
#=========================================================================================#


# class that represents a protected HTTP server that allows handling multiple requests concurrently and limits the number of concurrent connections
class ProtectedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True #enable multi-threaded operations for handling multiple connections for server
    request_queue_size = MAX_QUEUE_SIZE #set the maximum number of connections allowed in the server's queue at once
    request_semaphore = None #represents requests semaphore for limiting number of concurrent connections
    rate_limit_dict = {} #represents rate limit dictionary for each IP address {IP: [window_start, count]}
    captcha_dict = {} #represents captcha dictionary for each IP address {IP: captcha_code}
    pow_dict = {} #represents PoW dictionary for each IP address {IP: (nonce, target, timestamp)}

    # constructor of default HTTP server class
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # initialize our requests semaphore
        self.request_semaphore = threading.Semaphore(MAX_CONNECTIONS)


    # override get_request method to use our requests semaphore to limit number of connections
    def get_request(self):
        # get socket and address from original get_request method
        sock, addrr = super().get_request()

        # try to acquire the requests semaphore
        if not self.request_semaphore.acquire(blocking=False):
            try:
                # if couldn't acquire the semaphore send a "503 Service Unavailable" response
                sock.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except:
                pass

            # close the socket connection and return uninitialized socket
            sock.close() #close the socket connection
            return (sock, addrr) #return uninitialized socket

        # set timeout for socket and return initialized socket
        sock.settimeout(SOCKET_TIMEOUT) #set the timeout for the socket 
        return (sock, addrr) #return the socket and address


    # override process_request method to release our requests semaphore after the request is processed
    def process_request(self, request, client_address):
        try:
            # call the original process_request method for processing request
            super().process_request(request, client_address)
        finally:
            # release our requests semaphore after processing the request
            self.request_semaphore.release()


    # override handle_error method
    def handle_error(self, request, client_address):
        return


# handler class for handeling incoming HTTP requests for the HTTP server
class Handler(BaseHTTPRequestHandler):
    # override the handle method to manage exceptions
    def handle(self):
        try: 
            # call the base class method to handle the request
            super().handle()
        # if socket timeout occurs, return and continue server operations
        except socket.timeout:
            return
        # if other exeption occurs, return and continue server operations
        except:
            return


    # method for sending HTML response with status code and contents
    def send_html(self, status_code, html):
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(html.encode())


    # method for sending HTTP redirect response with status code
    def send_redirect(self, status_code, page):
        self.send_response(status_code)
        self.send_header('Location', page)
        self.end_headers()


    # method for retriving the client's IP address from the request
    def get_client_ip(self):
        forward_header = self.headers.get('X-Forwarded-For') #get the "X-Forwarded-For" header (if available)
        # check if we received "X-Forwarded-For" header, if so we return first IP address
        if forward_header:
            return (forward_header.split(',')[0].strip(), True)
        # else we return connection IP address
        else:
            return (self.client_address[0], False)


    # method for checking if ip is rate limited
    def check_rate_limit(self, ip):
        # get current time and ip_window from rate_limit_dict
        current_time = time.time()
        ip_window = self.server.rate_limit_dict.get(ip)

        # if IP address is new or it's window time has passed we update rate_limit_dict 
        if not ip_window or current_time - ip_window[0] > WINDOW_TIMEOUT:
            self.server.rate_limit_dict[ip] = [current_time, 1]
            return False

        # if IP address request counter exceedes the maximum requests
        if ip_window[1] >= MAX_REQUESTS:
            return True

        # increment the IP address counter if not rate limited
        ip_window[1] += 1
        return False


    # method for creating captcha code for IP address
    def create_captcha(self, ip):
        # generate 16-chracter captcha code and save it in captcha_dict for IP
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        self.server.captcha_dict[ip] = code

        # return the generated captcha code
        return code


    # method for verifing captcha code for IP address
    def verify_captcha(self, ip, captcha_code):
        # get captcha code that assosiated with IP address
        ip_captcha = self.server.captcha_dict.get(ip, '')

        # return result if given captcha matches stored IP captcha
        return ip_captcha == captcha_code


    # method for generating Proof-of-Work challenge for given IP (Hard task)
    def create_pow(self, ip):
        # generate a random 64-bit nonce for Proof-of-Work challenge
        nonce = random.getrandbits(64).to_bytes(8, 'big')

        # calculate the target value based formula: target = 2^(256 − POW_DIFFICULTY) − 1
        target = (1 << (256 - POW_DIFFICULTY)) - 1

        # store the Proof-of-Work challenge for the given IP in pow_dict
        self.server.pow_dict[ip] = (nonce, target, time.time())

        # return the nonce and target as the challenge for the client to solve
        return (nonce, target)


    # method to verify the Proof-of-Work submitted by the client for the given IP
    def verify_pow(self, ip, counter_hex):
        try:
            # retrieve the Proof-of-Work challenge stored for the given IP from pow_dict
            ip_challenge = self.server.pow_dict.get(ip)
            counter = bytes.fromhex(counter_hex) #convert the counter given from hex

            # check if Proof-of-Work challenge exists for the IP, if not we return false
            if not ip_challenge:
                return False
            
            # get the Proof-of-Work challenge parameters for given IP
            nonce, target, start_timestamp = ip_challenge

            # check if challenge has expired, if so return false
            if time.time() - start_timestamp > POW_TIMEOUT:
                return False

            # caluclate the SHA-256 result with nonce and given counter
            hash_result = hashlib.sha256(nonce + counter).digest()

            # return the result of verification, check if counter hash meets the target limitation
            return int.from_bytes(hash_result, 'big') <= target

        # if exeption occurs we return false
        except:
            return False


    # override the do_GET method for GET requests for protected page verification
    def do_GET(self):
        # get client IP address and status code
        ip, is_forward = self.get_client_ip()
        status_code = 200

        # get the path and query from our parsed path
        parsed_path = urllib.parse.urlparse(self.path)
        path, query = parsed_path.path, urllib.parse.parse_qs(parsed_path.query)

        # check if path is "/protected"
        if path == '/protected':
            # initialize captcha, pow and error message strings for html
            captcha_section, pow_section, error_message = '', '', ''
            error_query = query.get('error', [''])[0] #get error from query if available

            # check if error query given, if so we show appropriate message
            if error_query:
                # check if rate_limit in error query, if so show rate limit error message
                if error_query == 'rate_limit':
                    error_message = '<div class="error">Rate limit exceeded!</div>'
                    status_code = 429  

                # check captcha in error query, if so show captcha error message
                elif error_query == 'captcha':
                    error_message = '<div class="error">Invalid CAPTCHA!</div>'
                    status_code = 403

                # check pow in error query, if so show pow error message
                elif error_query == 'pow':
                    error_message = '<div class="error">Proof-of-Work failed!</div>'
                    status_code = 422

            # check if captcha enabled, if so show captcha section
            if USE_CAPTCHA:
                # create randon captcha code for IP address
                captcha_code = self.create_captcha(ip)

                # create captcha section with related fields and captcha code
                captcha_section = f'''
                    <label for="captcha_input" style="text-decoration: underline;">Enter CAPTCHA:</label>
                    <p style="text-align: center;"><strong id="captcha_code">{captcha_code}</strong></p>
                    <input type="text" name="captcha_input" id="captcha_input" required>
                '''

            # check if PoW enabled and not human user, if so show PoW section
            if USE_POW and is_forward:
                # create pow for IP address and get nonce and target values
                nonce, target = self.create_pow(ip)

                # create PoW section with related fields with nonce and target
                pow_section = f'''
                    <input type="hidden" name="pow_nonce" value="{nonce.hex()}">
                    <input type="hidden" name="pow_target" value="{hex(target)}">
                    <label for="pow_counter" style="text-decoration: underline;">Enter Proof-of-Work:</label>
                    <p class="pow-note" style="text-align: center;">SHA256(nonce||counter) &lt; {hex(target)}</p>
                    <input type="text" name="pow_counter" id="pow_counter" required>
                '''

            # retrn html page with all related fields based on our defence flags
            return self.send_html(status_code, PROTECTED_PAGE.format(captcha_section=captcha_section, pow_section=pow_section, error_message=error_message))

        # check if path is "/"
        if path == '/':
            # check if rate limit enabled, if so check if IP is rate limited
            if USE_RATE_LIMIT:
                # check if ip is rate limited, if so redirect back to "/protected"
                if self.check_rate_limit(ip):
                    return self.send_redirect(302, '/protected?error=rate_limit')

            # check if captcha enabled, if so check if captcha valid
            if USE_CAPTCHA:
                # get captcha code from query
                captcha_code = query.get('captcha_input', [''])[0]

                # check if captcha code matches one stored in captcha_dict, if not redirect back to "/protected"
                if not self.verify_captcha(ip, captcha_code):
                    return self.send_redirect(302, '/protected?error=captcha')

            # check if PoW enabled and not human user, if so check if PoW valid
            if USE_POW and is_forward:
                # get nonce, target and counter from query
                nonce = query.get('pow_nonce', [''])[0]
                target = query.get('pow_target', [''])[0]
                counter = query.get('pow_counter', [''])[0]

                # check that all parameters are valid and that PoW verification is valid, if not redirect back to "/protected"
                if not nonce or not target or not self.verify_pow(ip, counter):
                    return self.send_redirect(302, '/protected?error=pow')

            # if all checks passed return success html page
            return self.send_html(200, SUCCESS_PAGE)

        # if path is invalid fallback to 404 Not Found
        self.send_response(404)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b'404 Not Found')


# represents main for protected HTTP server
if __name__ == '__main__':
    try:
        # start our HTTP server in our desired IP and port
        print(f'[*] Server running on {SERVER_IP}:{SERVER_PORT} with defenses: rate-limit={USE_RATE_LIMIT}, captcha={USE_CAPTCHA}, pow={USE_POW}')
        server = ProtectedHTTPServer((SERVER_IP, SERVER_PORT), Handler)
        server.serve_forever()

    # if we receive keyboard interrupt we close server
    except KeyboardInterrupt:
        print('[*] Stopping HTTP server...')
        server.server_close()
        print('[*] HTTP server stopped. Exiting.')