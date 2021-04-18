# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Adapted from Synapse:
#  https://github.com/matrix-org/synapse/blob/1016f303e58b1305ed5b3572fde002e1273e0fc0/synapse/crypto/context_factory.py#L77


import logging

import idna
import os
from OpenSSL import SSL, crypto
from service_identity import VerificationError
from service_identity.pyopenssl import verify_hostname, verify_ip_address
from twisted.internet._sslverify import _defaultCurveName
from twisted.internet.abstract import isIPAddress, isIPv6Address
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.internet.ssl import CertificateOptions, ContextFactory, TLSVersion, platformTrust
from twisted.python.failure import Failure
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer

logger = logging.getLogger(__name__)

# Based on https://github.com/matrix-org/synapse/blob/b685c5e7f193b1afb95b96d0a827d74f7691faef/synapse/crypto/context_factory.py#L46
class ServerContextFactory(ContextFactory):
    """Factory for PyOpenSSL SSL contexts that are used to handle incoming
    connections.

    TODO: replace this with an implementation of IOpenSSLServerConnectionCreator,
    per https://github.com/matrix-org/synapse/issues/1691
    """

    def __init__(self, tls_certificate_file, tls_private_key_file):
        # TODO: once pyOpenSSL exposes TLS_METHOD and SSL_CTX_set_min_proto_version,
        # switch to those (see https://github.com/pyca/cryptography/issues/5379).
        #
        # note that, despite the confusing name, SSLv23_METHOD does *not* enforce SSLv2
        # or v3, but is a synonym for TLS_METHOD, which allows the client and server
        # to negotiate an appropriate version of TLS constrained by the version options
        # set with context.set_options.
        #
        self._context = SSL.Context(SSL.SSLv23_METHOD)
        self.read_tls_certificate(tls_certificate_file)
        self.configure_context(self._context, tls_certificate_file, self.read_tls_private_key(tls_private_key_file))

    @staticmethod
    def configure_context(context, tls_certificate, tls_private_key):
        try:
            _ecCurve = crypto.get_elliptic_curve(_defaultCurveName)
            context.set_tmp_ecdh(_ecCurve)
        except Exception:
            logger.exception("Failed to enable elliptic curve for TLS")

        context.set_options(
            SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1
        )
        context.use_certificate_chain_file(tls_certificate)
        context.use_privatekey(tls_private_key)

        # https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
        context.set_cipher_list(
            "ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:ECDH+AES128:!aNULL:!SHA1:!AESCCM"
        )

    def getContext(self):
        return self._context

    # Based on https://github.com/matrix-org/synapse/blob/b685c5e7f193b1afb95b96d0a827d74f7691faef/synapse/config/tls.py#L482
    def read_tls_certificate(self, tls_certificate_file) -> crypto.X509:
        """Reads the TLS certificate from the configured file, and returns it

        Returns:
            The certificate
        """
        cert_path = tls_certificate_file
        logger.info("Loading TLS certificate from %s", cert_path)
        cert_pem = self.read_file(cert_path, "tls_certificate_path")
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        return cert

    # Based on https://github.com/matrix-org/synapse/blob/b685c5e7f193b1afb95b96d0a827d74f7691faef/synapse/config/tls.py#L507
    def read_tls_private_key(self, tls_private_key_file) -> crypto.PKey:
        """Reads the TLS private key from the configured file, and returns it

        Returns:
            The private key
        """
        private_key_path = tls_private_key_file
        logger.info("Loading TLS key from %s", private_key_path)
        private_key_pem = self.read_file(private_key_path, "tls_private_key_path")
        return crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)

    # Based on https://github.com/matrix-org/synapse/blob/b685c5e7f193b1afb95b96d0a827d74f7691faef/synapse/config/_base.py#L201
    def read_file(cls, file_path, config_name):
        with open(file_path) as file_stream:
            return file_stream.read()

@implementer(IPolicyForHTTPS)
class ClientTLSOptionsFactory(object):
    """Factory for Twisted SSLClientConnectionCreators that are used to make connections
    to remote servers for federation.
    Uses one of two OpenSSL context objects for all connections, depending on whether
    we should do SSL certificate verification.
    get_options decides whether we should do SSL certificate verification and
    constructs an SSLClientConnectionCreator factory accordingly.
    """

    def __init__(self):
        # Use CA root certs provided by OpenSSL
        trust_root = platformTrust()

        # "insecurelyLowerMinimumTo" is the argument that will go lower than
        # Twisted's default, which is why it is marked as "insecure" (since
        # Twisted's defaults are reasonably secure). But, since Twisted is
        # moving to TLS 1.2 by default, we want to respect the config option if
        # it is set to 1.0 (which the alternate option, raiseMinimumTo, will not
        # let us do).
        minTLS = TLSVersion.TLSv1_2

        self._verify_ssl = CertificateOptions(
            trustRoot=trust_root, insecurelyLowerMinimumTo=minTLS
        )
        self._verify_ssl_context = self._verify_ssl.getContext()
        self._verify_ssl_context.set_info_callback(self._context_info_cb)

    def get_options(self, host):
        ssl_context = self._verify_ssl_context

        return SSLClientConnectionCreator(host, ssl_context)

    @staticmethod
    def _context_info_cb(ssl_connection, where, ret):
        """The 'information callback' for our openssl context object."""
        # we assume that the app_data on the connection object has been set to
        # a TLSMemoryBIOProtocol object. (This is done by SSLClientConnectionCreator)
        tls_protocol = ssl_connection.get_app_data()
        try:
            # ... we further assume that SSLClientConnectionCreator has set the
            # '_synapse_tls_verifier' attribute to a ConnectionVerifier object.
            tls_protocol._synapse_tls_verifier.verify_context_info_cb(
                ssl_connection, where
            )
        except:  # noqa: E722, taken from the twisted implementation
            logger.exception("Error during info_callback")
            f = Failure()
            tls_protocol.failVerification(f)

    def creatorForNetloc(self, hostname, port):
        """Implements the IPolicyForHTTPS interace so that this can be passed
        directly to agents.
        """
        return self.get_options(hostname)


@implementer(IOpenSSLClientConnectionCreator)
class SSLClientConnectionCreator(object):
    """Creates openssl connection objects for client connections.

    Replaces twisted.internet.ssl.ClientTLSOptions
    """

    def __init__(self, hostname, ctx):
        self._ctx = ctx
        self._verifier = ConnectionVerifier(hostname)

    def clientConnectionForTLS(self, tls_protocol):
        context = self._ctx
        connection = SSL.Connection(context, None)

        # as per twisted.internet.ssl.ClientTLSOptions, we set the application
        # data to our TLSMemoryBIOProtocol...
        connection.set_app_data(tls_protocol)

        # ... and we also gut-wrench a '_synapse_tls_verifier' attribute into the
        # tls_protocol so that the SSL context's info callback has something to
        # call to do the cert verification.
        setattr(tls_protocol, "_synapse_tls_verifier", self._verifier)
        return connection


class ConnectionVerifier(object):
    """Set the SNI, and do cert verification

    This is a thing which is attached to the TLSMemoryBIOProtocol, and is called by
    the ssl context's info callback.
    """

    # This code is based on twisted.internet.ssl.ClientTLSOptions.

    def __init__(self, hostname):
        if isIPAddress(hostname) or isIPv6Address(hostname):
            self._hostnameBytes = hostname.encode("ascii")
            self._is_ip_address = True
        else:
            # twisted's ClientTLSOptions falls back to the stdlib impl here if
            # idna is not installed, but points out that lacks support for
            # IDNA2008 (http://bugs.python.org/issue17305).
            #
            # We can rely on having idna.
            self._hostnameBytes = idna.encode(hostname)
            self._is_ip_address = False

        self._hostnameASCII = self._hostnameBytes.decode("ascii")

    def verify_context_info_cb(self, ssl_connection, where):
        if where & SSL.SSL_CB_HANDSHAKE_START and not self._is_ip_address:
            ssl_connection.set_tlsext_host_name(self._hostnameBytes)

        if where & SSL.SSL_CB_HANDSHAKE_DONE:
            try:
                if self._is_ip_address:
                    verify_ip_address(ssl_connection, self._hostnameASCII)
                else:
                    verify_hostname(ssl_connection, self._hostnameASCII)
            except VerificationError:
                f = Failure()
                tls_protocol = ssl_connection.get_app_data()
                tls_protocol.failVerification(f)
