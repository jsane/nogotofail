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
from nogotofail.mitm import util
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm.util import tls
from nogotofail.mitm.util.tls.types import TlsRecord


@handler(handlers, default=True)
class PassThruHandler(LoggingHandler):

    name = "passthru"
    description = (
        "A do nothing pass thru handler required for certain checks in data handlers")
    success = True

    def on_request(self, request):
        # do nothing
        try:
            self.success = True
        except:
            pass
        return request

    def on_close(self, handler_initiated):
        super(PassThruHandler, self).on_close(handler_initiated)
        if not self.success:
            self.log_event(
                logging.INFO,
                connection.AttackEvent(
                    self.connection, self.name, False,
                    None))

    def on_response(self, response):
        if not self.success and self.ssl:
            self.log(logging.INFO, "Passthru handler failed!")

        return super(PassThruHandler, self).on_response(response)
