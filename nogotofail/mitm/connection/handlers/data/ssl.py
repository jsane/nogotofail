r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import logging
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm.util import ssl2, tls, vuln

class _TlsRecordHandler(DataHandler):
    """Base class for a handler that acts on TlsRecords in a Tls connection.

    Handlers should subclass this and implement on_tls_request and on_tls_response
    to handle TlsRecords in the connection.

    This class handles buffering and dealing with multiple records in one message
    and can be used for active or passive handlers as needed.
    """
    ssl = False
    class _TlsRecordBuffer():
        MAX_BUFFER = 65536
        def __init__(self):
            self.buffer = ""
            self.should_buffer = True
    client_buffer = None
    server_buffer = None

    def on_tls_request(self, record):
        """Called when the client sends a tls record to the server

        record: tls.types.TlsRecord the client sent
        Returns the bytes to be sent in place of the record
        """
        return record.to_bytes()

    def on_tls_response(self, record):
        """Called when the server sends a tls record to the client

        record: tls.types.TlsRecord the client sent
        Returns the bytes to be sent in place of the record
        """
        return record.to_bytes()

    def on_ssl(self, client_hello):
        self.ssl = True
        self.client_buffer = _TlsRecordHandler._TlsRecordBuffer()
        self.server_buffer = _TlsRecordHandler._TlsRecordBuffer()

    def _handle_message(self, message, buffer, record_fn):
        """Build a response calling record_fn on all the TlsRecords in message

        message: bytes to parse as TlsRecords
        record_fn: one of on_tls_request, on_tls_response to handle the record
        Returns tuple containing the bytes to send for all the records handled and any remaining unparsed data
        """
        out = ""
        message = buffer.buffer + message
        buffer.buffer = ""
        remaining = message
        while remaining:
            record = None
            try:
                record, remaining = tls.parse_tls(remaining, throw_on_incomplete=True)
            except tls.types.TlsNotEnoughDataError:
                if buffer.should_buffer:
                    buffer.buffer = remaining
                    if len(buffer.buffer) >= buffer.MAX_BUFFER:
                        buffer.buffer = ""
                return out
            if not record:
                return out
            record_bytes = record_fn(record)
            # In a passive handler on_tls_* could return None, so make sure not to cause an error
            # out doesn't matter on a passive handler.
            if record_bytes:
                out += record_bytes
            # Once we read a CHANGE_CIPHER_SPEC stop trying to buffer, its probably encrypted
            if record.content_type == record.CONTENT_TYPE.CHANGE_CIPHER_SPEC:
                buffer.should_buffer = False
        return out

    def on_request(self, request):
        if not self.ssl:
            return request
        return self._handle_message(request, self.client_buffer, self.on_tls_request)

    def on_response(self, response):
        if not self.ssl:
            return response
        return self._handle_message(response, self.server_buffer, self.on_tls_response)

@handler.passive(handlers)
class InsecureCipherDetectionHandler(DataHandler):
    name = "insecurecipherdetection"
    description = "Detect insecure ciphers in TLS Client Hellos"

    def _handle_bad_ciphers(self, ciphers, message):
            self.log(logging.ERROR, message)
            self.log_attack_event(data=ciphers)
            self.connection.vuln_notify(vuln.VULN_WEAK_CIPHER)

    def on_ssl(self, client_hello):

        all_ciphers = [str(c) for c in client_hello.ciphers]
        self.logger.info( "Client ciphers %s", all_ciphers)

        # Check for anon ciphers, these don't verify the identity of the
        # endpoint
        anon_ciphers = [str(c) for c in client_hello.ciphers if "_anon_" in str(c)]
        if anon_ciphers:
            self.logger.info( "Anonymous ciphers used")




@handler.passive(handlers)
class WeakTLSVersionDetectionHandler(DataHandler):
    name = "weaktlsversiondetection"
    description = "Detect versions of the TLS/SSL protocols that are known to be weak"

    def on_ssl(self, client_hello):
        all_ciphers = [str(c) for c in client_hello.ciphers]
        self.logger.info( "Client ciphers %s", all_ciphers)
