import unittest
import hashlib
import random

from web3 import Web3, HTTPProvider

import asset
from context import secretstore

alice = asset.accounts["alice"]
alicepwd = asset.passwords["alice"]
rpc_alice = asset.httpRpc["alice"]
ss_alice = asset.httpSS["alice"]
node1 = asset.nodes["node1"]
node2 = asset.nodes["node2"]
node3 = asset.nodes["node3"]

class SSTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _retval_exists(self, retval):
        self.assertIsNotNone(retval)
        self.assertFalse(not retval)
    
    def _random_sha256(self):
        sha256 = hashlib.sha256()
        sha256.update(repr(random.random()).encode("utf-8"))
        return sha256.hexdigest()

    def setUp(self):
        self.web3 = Web3(HTTPProvider(rpc_alice))
        self.ss = secretstore.SecretStore(self.web3, ss_alice)

    def tearDown(self):
        pass

    def test_a_should_sign_raw_hash(self):
        sha256 = hashlib.sha256()
        sha256.update(b"lololol")
        docID =sha256.hexdigest()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        self._retval_exists(signedDocID)

    def test_b_should_generate_server_key(self):
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        self._retval_exists(skey)
    
    def test_c_should_generate_document_key(self):
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self._retval_exists(dkey)
    
    def test_d_should_store_document_key(self):
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        res = self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)
        self.assertIsNotNone(res)
        self.assertTrue(type(res) is str)
    
    def test_e_should_generate_server_and_document_key(self):
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        dkey = self.ss.session.generateServerAndDocumentKey(docID, signedDocID, 1)
        self._retval_exists(dkey)

    def test_f_should_shadow_retrieve_document_key(self):
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)
        shadowRetrievedKey = self.ss.session.shadowRetrieveDocumentKey(docID, signedDocID)
        self._retval_exists(shadowRetrievedKey)

    def test_g_should_retrieve_document_key(self):
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)
        retrievedKey = self.ss.session.retrieveDocumentKey(docID, signedDocID)
        self._retval_exists(retrievedKey)
    
    def test_h_should_encrypt_document(self):
        hexDoc = Web3.toHex(text="lololololol")
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)
        retrievedKey = self.ss.session.retrieveDocumentKey(docID, signedDocID)
        encryptedDoc = self.ss.encrypt(alice, alicepwd, retrievedKey, hexDoc)
        self._retval_exists(encryptedDoc)

    def test_i_should_decrypt_document(self):
        hexDoc = Web3.toHex(text="lololololol")
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)
        retrievedKey = self.ss.session.retrieveDocumentKey(docID, signedDocID)
        encryptedDoc = self.ss.encrypt(alice, alicepwd, retrievedKey, hexDoc)
        decryptedDoc = self.ss.decrypt(alice, alicepwd, retrievedKey, encryptedDoc)
        self._retval_exists(decryptedDoc)

    def test_j_should_shadow_decrypt_document(self):
        hexDoc = Web3.toHex(text="lololololol")
        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)
        retrievedKey = self.ss.session.retrieveDocumentKey(docID, signedDocID)
        encryptedDoc = self.ss.encrypt(alice, alicepwd, retrievedKey, hexDoc)
        shadowRetrievedKey = self.ss.session.shadowRetrieveDocumentKey(docID, signedDocID)
        decryptedDoc = self.ss.shadowDecrypt(alice,
                                             alicepwd,
                                             shadowRetrievedKey.decrypted_secret,
                                             shadowRetrievedKey.common_point,
                                             shadowRetrievedKey.decrypt_shadows,
                                             encryptedDoc)
        self._retval_exists(decryptedDoc)
    
    def test_k_should_schnorr_sign(self):
        sha256 = hashlib.sha256()
        sha256.update(b"bongocat")

        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)

        signedMessage = self.ss.session.signSchnorr(docID, signedDocID, sha256.hexdigest())
        self._retval_exists(signedMessage)

    def test_l_should_ecdsa_sign(self):
        sha256 = hashlib.sha256()
        sha256.update(b"bongocat")

        docID = self._random_sha256()
        signedDocID = self.ss.signRawHash(alice, alicepwd, docID)
        skey = self.ss.session.generateServerKey(docID, signedDocID, 1)
        dkey = self.ss.generateDocumentKey(alice, alicepwd, skey)
        self.ss.session.storeDocumentKey(docID, signedDocID, dkey.common_point, dkey.encrypted_point)

        signedMessage = self.ss.session.signEcdsa(docID, signedDocID, sha256.hexdigest())
        self._retval_exists(signedMessage)
    
    def test_m_should_compute_hash_of_node_ids(self):
        the_hash = self.ss.serversSetHash([node1, node2])
        self._retval_exists(the_hash)

    @unittest.skip
    def test_n_should_change_set_of_nodes(self):
        """ This is not working right now"""

        nodeIDsNewSet = [node1, node2]
        hashOldSet = self.ss.serversSetHash([node1, node2, node3])
        hashNewSet = self.ss.serversSetHash(nodeIDsNewSet) 
        
        signatureOldSet = self.ss.signRawHash(alice, alicepwd, hashOldSet)
        signatureNewSet = self.ss.signRawHash(alice, alicepwd, hashNewSet)
        
        something = self.ss.session.nodesSetChange(nodeIDsNewSet, 
                                                   signatureOldSet, 
                                                   signatureNewSet)
        self.assertIsNotNone(something)
        self.assertTrue(type(something) is str)

    @unittest.skip
    def test_o_should_change_set_of_nodes_back(self):
        """ This is not working right now"""

        nodeIDsNewSet = [node1, node2, node3]
        hashOldSet = self.ss.serversSetHash([node1, node2])
        hashNewSet = self.ss.serversSetHash(nodeIDsNewSet) 
        
        signatureOldSet = self.ss.signRawHash(alice, alicepwd, hashOldSet)
        signatureNewSet = self.ss.signRawHash(alice, alicepwd, hashNewSet)
        
        something = self.ss.session.nodesSetChange(nodeIDsNewSet, 
                                                   signatureOldSet, 
                                                   signatureNewSet)
        self.assertIsNotNone(something)
        self.assertTrue(type(something) is str)

if __name__ == '__main__':
    unittest.main()
