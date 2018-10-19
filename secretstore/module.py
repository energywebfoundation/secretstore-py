# -*- coding: utf-8 -*-
"""
.. module:: module
   :synopsis: Contains abstraction of Parity's secretstore module: https://wiki.parity.io/JSONRPC-secretstore-module

.. moduleauthor:: Adam Nagy <adam.nagy@energyweb.org>

"""

import logging

from web3 import Web3
try:
    from web3.datastructures import AttributeDict
except ModuleNotFoundError:
    from web3.utils.datastructures import AttributeDict

from .session import (
    Session,
    SecretStoreSessionError
)

from .utils import (
    add_0x,
    get_default_logger
)


class SecretStore(object):
    """
    The class holding together the secretstore module API- and session calls.

    Args:
        web3 (:class:`web3.Web3`, optional): The :class:`web3.Web3` instance. Defaults to None, in which case
            it tries to `auto import <https://web3py.readthedocs.io/en/stable/providers.html#how-automated-detection-works>`_ it.
        ss_endpoint_uri (str, optional): The endpoint where Secret Store is listening for requests (for sessions). Defaults to None.
        logger (:py:obj:`logging.Logger`, optional): The logger object. 
            Defaults to None and instantiates a default logger in this case with log level *INFO*.

    Attributes:
        web3 (:class:`web3.Web3`): The :class:`web3.Web3` instance.
        session (:class:`.Session`): The :class:`.Session` instance.

    Returns:
        str: The signed hash.
    """

    def __init__(self, web3: Web3=None, ss_endpoint_uri: str=None, logger: logging.Logger=None):

        self.logger = logger if logger is not None else get_default_logger(
            __name__)

        if not ss_endpoint_uri:
            self.logger.warning("SecretStore URL was not given, you will not be able to call sessions. "
                + "Didn't you forget to pass `ss_endpoint_uri`?")
        else:
            self.session = Session(ss_endpoint_uri, logger)

        if web3 is None:
            self.logger.warning(
                "SecretStore: Web3 instance was not given, using \"auto import\" instead.")
            from web3.auto import w3
            self.web3 = w3
        else:
            self.web3 = web3

    def signRawHash(self, account: str, pwd: str, rawhash: str) -> str:
        """Computes recoverable ECDSA signatures.

        Typically used for signatures of server key id and signatures of nodes-set hash
        in the Secret Store.

        Args:
            account (str): The account of SS user.
            pwd (str): The password of SS user.
            rawhash (str): A 256-bit hash to be signed, e.g.: server key id or nodes-set hash.

        Returns:
            str: The signed hash.

        Raises:
            ValueError: If there is an error in the response.
        """

        return self.web3.manager.request_blocking(
            "secretstore_signRawHash",
            [Web3.toChecksumAddress(account), pwd,
             add_0x(rawhash)]
        )

    def encrypt(self, account, pwd, encrypted_key, hex_document) -> str:
        """ You can use it to encrypt a small document.

        An encryption key is needed, typically obtained from the store by running a 
        `document key retrieval session <https://wiki.parity.io/Secret-Store#document-key-retrieval-session>`_ 
        or a `server- and document key generation session <https://wiki.parity.io/Secret-Store#server-and-document-key-generation-session>`_.

        Args:
            account (str): The account of SS user.
            pwd (str): The password of SS user.
            encrypted_key (str): Document key encrypted with requester's public key.
            hex_document (str): Hex encoded document data.

        Returns:
            str: The encrypted secret document.

        Raises:
            ValueError: If there is an error in the response.
        """

        return self.web3.manager.request_blocking(
            "secretstore_encrypt",
            [Web3.toChecksumAddress(account), pwd,
             add_0x(encrypted_key),
             add_0x(hex_document)]
        )

    def decrypt(self, account: str, pwd: str, encrypted_key: str, encrypted_document: str) -> str:
        """This method can be used to decrypt document, encrypted by :func:`encrypt` method before.

        Args:
            account (str): The account of SS user.
            pwd (str): The password of SS user.
            encrypted_key (str): Document key encrypted with requester's public key.
            encrypted_document (str): Encrypted document data, returned by :func:`encrypt`

        Returns:
            str: The decrypted secret document.

        Raises:
            ValueError: If there is an error in the response.
        """

        return self.web3.manager.request_blocking(
            "secretstore_decrypt",
            [Web3.toChecksumAddress(account), pwd,
             add_0x(encrypted_key),
             add_0x(encrypted_document)]
        )

    def generateDocumentKey(self, account: str, pwd: str, server_key: str) -> AttributeDict:
        """Securely generates document key, so that it remains unknown to all key servers.

        Args:
            account (str): The account of SS user.
            pwd (str): The password of SS user.
            server_key (str): The server key, returned by a server key generating session.
        
        Returns:
            :class:`web3.datastructures.AttributeDict`: The document key.
        
        Raises:
            ValueError: If there is an error in the response.
        """

        return self.web3.manager.request_blocking(
            "secretstore_generateDocumentKey",
            [Web3.toChecksumAddress(account), pwd,
             add_0x(server_key)]
        )

    def shadowDecrypt(self, account, pwd, decrypted_secret, common_point, decrypt_shadows, encrypted_document) -> str:
        """This method can be used to decrypt document, encrypted by :func:`encrypt` method before. .
        
        Document key can be obtained by a 
        `document key shadow retrieval session <https://wiki.parity.io/Secret-Store#document-key-shadow-retrieval-session>`_

        Args:
            account (str): The account of SS user.
            pwd (str): The password of SS user.
            decrypted_secret (str): The hex-encoded decrypted secret portion of an encrypted document key.
            common_point (str): The hex-encoded common point portion of an encrypted document key.
            decrypt_shadows (str): The hex-encoded encrypted point portion of an encrypted document key.
            encrypted_document (str): Encrypted document data, returned by :func:`encrypt`.
        
        Returns:
            str: The decrypted secret document.
        
        Raises:
            ValueError: If there is an error in the response.
        """
        return self.web3.manager.request_blocking(
            "secretstore_shadowDecrypt",
            [Web3.toChecksumAddress(account), pwd,
             add_0x(decrypted_secret),
             add_0x(common_point),
             decrypt_shadows,
             add_0x(encrypted_document)]
        )

    def serversSetHash(self, node_ids: list) -> str:
        """Computes the hash of nodes ids, required to compute nodes set signature
         for manual `nodes set change session <https://wiki.parity.io/Secret-Store-Configuration#changing-the-configuration-of-a-set-of-servers>`_ . 

        Args:
            node_ids (list(str)): List of node ID's (public keys).

        Returns:
            str: The hash.
        
        Raises:
            ValueError: If there is an error in the response.
        """

        return self.web3.manager.request_blocking(
            "secretstore_serversSetHash",
            [node_ids]
        )
