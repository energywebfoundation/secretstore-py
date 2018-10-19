# -*- coding: utf-8 -*-
"""
.. module:: session
   :synopsis: Contains abstraction of Parity's secretstore sessions: https://wiki.parity.io/Secret-Store

.. moduleauthor:: Adam Nagy <adam.nagy@energyweb.org>

"""

import logging
from typing import Union

import requests
from requests.exceptions import RequestException
try:
    from web3.datastructures import AttributeDict
except ModuleNotFoundError:
    from web3.utils.datastructures import AttributeDict

from .utils import(
    remove_0x,
    get_default_logger,
    response_to_attrdict,
    response_to_str
)

class SecretStoreSessionError(RequestException):
    """ Thrown when an error has occured during the Secret Store session. 

    """

class Session(object):
    """
    The class holding together the secretstore session calls.

    Args:
        ss_endpoint_uri (str): The endpoint where Secret Store is listening for requests (for sessions).
        logger (:py:obj:`logging.Logger`, optional): The logger object. 
            Defaults to None and instantiates a default logger in this case with log level *INFO*.

    Attributes:
        ss_endpoint_uri (str): The endpoint where Secret Store is listening for requests (for sessions).
        logger (:py:obj:`logging.Logger`): The logger object. 

    Raises:
        ValueError: if the secret store's url is not given
    """

    __SEP = "/"

    def __init__(self, ss_endpoint_uri: str, logger: logging.Logger=None):

        self.logger = logger if logger is not None else get_default_logger(__name__)

        if not ss_endpoint_uri:
            self.logger.error("Secret Store endpoint was not given, please pass it as a string, e.g.: \"http://127.0.0.1:8090\"")
            raise ValueError("Secret store endpoint not specified.")

        self.ss_endpoint_uri = str(ss_endpoint_uri)
        if self.ss_endpoint_uri.endswith(Session.__SEP):
            self.ss_endpoint_uri = self.ss_endpoint_uri[:-1]

    def __query(self, f, *args, **kwargs):
        verbose = kwargs.pop("verbose", True)
        try:
            response = f(*args, **kwargs)
        except RequestException as re:
            if verbose:
                self.logger.error(re)
            raise

        if response.status_code != 200:
            re = SecretStoreSessionError(response=response)
            if verbose:
                self.logger.error("Secret store session error. Status code: {}".format(response.status_code))
                self.logger.error("Reason: {}".format(response.reason))
                self.logger.error("Json: {}".format(response.content))
                self.logger.error("Url: {}".format(response.url))
            raise re

        return response

    def __post(self, *args, **kwargs):
        return self.__query(requests.post, *args, **kwargs)

    def __get(self, *args, **kwargs):
        return self.__query(requests.get, *args, **kwargs)

    def __urlbuild(self, *args):
        return Session.__SEP.join(args)

    @response_to_str
    def generateServerKey(self, server_key_id: str, signed_server_key_id: str, threshold: Union[str, int], verbose=True) -> str:
        """Generates server keys.

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            threshold (str or int): Key threshold value. 
                Please consider the `guidelines <https://wiki.parity.io/>`_ when choosing this value.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: The hex-encoded public portion of the server key.

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`

        """

        return self.__post(self.__urlbuild(self.ss_endpoint_uri,
                                           "shadow",
                                           remove_0x(server_key_id),
                                           remove_0x(signed_server_key_id),
                                           str(threshold)),
                           verbose=verbose)

    @response_to_str
    def generateServerAndDocumentKey(self, server_key_id, signed_server_key_id, threshold, verbose=True) -> str:
        """Generating document key by one of the participating nodes.
        
        While it is possible (and more secure, if you’re not trusting the Secret Store nodes) 
        to run separate server key generation and document key storing sessions, 
        you can generate both keys simultaneously. 

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            threshold (str or int): Key threshold value. 
                Please consider the `guidelines <https://wiki.parity.io/>`_ when choosing this value.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: The hex-encoded document key, encrypted with requester's public key (ECIES encryption is used) .

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`

        """
        
        return self.__post(self.__urlbuild(self.ss_endpoint_uri,
                                           remove_0x(server_key_id),
                                           remove_0x(signed_server_key_id),
                                           str(threshold)),
                           verbose=verbose)

    @response_to_attrdict
    def shadowRetrieveDocumentKey(self, server_key_id, signed_server_key_id, verbose=True) -> AttributeDict:
        """This session is a preferable way of retrieving previously generated document key.  

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            :class:`web3.datastructures.AttributeDict`: The hex-encoded decrypted_secret, common_point and decrypt_shadows fields.

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`

        """
        
        return self.__get(self.__urlbuild(self.ss_endpoint_uri,
                                          "shadow",
                                          remove_0x(server_key_id),
                                          remove_0x(signed_server_key_id)),
                          verbose=verbose)
    @response_to_str
    def retrieveDocumentKey(self, server_key_id, signed_server_key_id, verbose=True) -> str:
        """ Fetches the document key from the secret store.  

        This is the lighter version of the 
        `document key shadow retrieval <https://wiki.parity.io/Secret-Store#document-key-shadow-retrieval-session>`_ session, 
        which returns final document key (though, encrypted with requester public key) if you have enough trust in 
        the Secret Store nodes. During document key shadow retrieval session, document key is not reconstructed 
        on any node, but it requires Secret Store client either to have an access to Parity RPCs, or 
        to run some EC calculations to decrypt the document key.

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: The hex-encoded document key, encrypted with requester public key (ECIES encryption is used).

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`

        """
        
        return self.__get(self.__urlbuild(self.ss_endpoint_uri,
                                          remove_0x(server_key_id),
                                          remove_0x(signed_server_key_id)),
                          verbose=verbose)
    
    @response_to_str
    def signSchnorr(self, server_key_id, signed_server_key_id, message_hash, verbose=True) -> str:
        """ Schnorr signing session, for computing Schnorr signature of a given message hash. 

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            message_hash (str): The 256-bit hash of the message that needs to be signed.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: The hex-encoded Schnorr signature (serialized as c || s), encrypted with requester public key (ECIES encryption is used).

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`

        """
        
        return self.__get(self.__urlbuild(self.ss_endpoint_uri,
                                          "schnorr",
                                          remove_0x(server_key_id),
                                          remove_0x(signed_server_key_id),
                                          remove_0x(message_hash)),
                          verbose=verbose)
    
    @response_to_str
    def signEcdsa(self, server_key_id, signed_server_key_id, message_hash, verbose=True) -> str:
        """ ECDSA signing session, for computing ECDSA signature of a given message hash. 

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            message_hash (str): The 256-bit hash of the message that needs to be signed.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: The hex-encoded ECDSA signature (serialized as r || s || v ), encrypted with requester public key (ECIES encryption is used).

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`

        """
        
        return self.__get(self.__urlbuild(self.ss_endpoint_uri,
                                          "ecdsa",
                                          remove_0x(server_key_id),
                                          remove_0x(signed_server_key_id),
                                          remove_0x(message_hash)),
                          verbose=verbose)

    @response_to_str
    def storeDocumentKey(self, server_key_id, signed_server_key_id, common_point, encrypted_point, verbose=True) -> str:
        """ Binds an externally-generated document key to a server key. 
        
        Useable after a `server key generation session <https://wiki.parity.io/Secret-Store#server-key-generation-session>`_ . 

        Args:
            server_key_id (str): The server key ID.
            signed_server_key_id (str): The server key ID signed by the SS user.
            common_point (str): The hex-encoded common point portion of encrypted document key.
            encrypted_point (str): The hex-encoded encrypted point portion of encrypted document key.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: Empty string if everything was OK (status code 200).

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`
        """
        
        return self.__post(self.__urlbuild(self.ss_endpoint_uri,
                                           "shadow",
                                           remove_0x(server_key_id),
                                           remove_0x(signed_server_key_id),
                                           remove_0x(common_point),
                                           remove_0x(encrypted_point)),
                           verbose=verbose)

    @response_to_str
    def nodesSetChange(self, node_ids_new_set, signature_old_set, signature_new_set, verbose=True) -> str:
        """ Node set change session.
        
        Requires all added, removed and stable nodes to be online for the duration of the session. 
        Before starting the session, you’ll need to generate two administrator’s signatures: `old set` 
        signature and `new set` signature. To generate these signatures, the Secret Store RPC methods should 
        be used: `serversSetHash` and `signRawHash`. 
        
        Args:
            node_ids_new_set (list(str)): Node IDs of the `new set`.
            signature_old_set (str): ECDSA signature of all online node IDs `keccak(ordered_list(staying + added + removing))`.
            signature_new_set (str): ECDSA signature of node IDs that should stay in the Secret Store after the session ends `keccak(ordered_list(staying + added))`.
            verbose (bool): Whether to log errors. Default: True.

        Returns:
            str: Empty string (probably).

        Raises:
            :class:`SecretStoreSessionError`, :class:`requests.RequestException`
        """

        url = self.__urlbuild(self.ss_endpoint_uri,
                              "admin",
                              "servers_set_change",
                              remove_0x(signature_old_set),
                              remove_0x(signature_new_set))
        
        return self.__post(url, json=node_ids_new_set, verbose=verbose)
