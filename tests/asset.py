import os
import json

accounts = {
    "alice": "0x3144de21da6de18061f818836fa3db8f3d6b6989",
    "bob": "0x6c4b8b199a41b721e0a95df9860cf0a18732e76d",
    "charlie": "0x8b2c16e09bfb011c5e4883cedb105124ccf01af7",
}

passwords = {
    "alice": open(os.path.join(os.path.dirname(__file__), "../nodes_ss_dev/alice.pwd")).read(),
    "bob": open(os.path.join(os.path.dirname(__file__), "../nodes_ss_dev/bob.pwd")).read(),
    "charlie": open(os.path.join(os.path.dirname(__file__), "../nodes_ss_dev/charlie.pwd")).read(),
}

httpSS = {
    "alice": "http://127.0.0.1:8090",
    "bob": "http://127.0.0.1:8091",
    "charlie": "http://127.0.0.1:8092",
}

httpRpc = {
    "alice": "http://localhost:8545",
    "bob": "http://localhost:8547",
    "charlie": "http://localhost:8549",
}

nodes = {
    "node1": "0x22417f6b9ecbaafbd10f33797161aaf0b8e74a0ce3aea19bb32b92c081e82780346c6f4f7aa619a8b3841f057dac8d31b8f75a241357420b25e9420b3918ac4b",
    "node2": "0x413ecc85852cc4087ac8527c76be43cba57a5015f7a48da29c9c9123877474f8ac2406657274abfeee68bfc31c791d44358830e5983a2dba8b4235bd03253f0e",
    "node3": "0xdc7452498e4b90f1c20178a5ea73c9d38626cc3d2199b4a110ec88fdb000be6f7da81779a4bbd743772eada02d523db54f1bea31cdc915c20ec377eb5336be81",

}
