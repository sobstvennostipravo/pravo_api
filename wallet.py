from web3 import Web3
import yaml
import pickle

class Wallet(object):
    def __init__(self, yaml_fname, provider):
        self.known_session = {}
        self.web3 = Web3(Web3.HTTPProvider(provider) if provider.find("//") > 0 else Web3.IPCProvider(provider))
        with open(yaml_fname, 'r') as f:
            self.y = yaml.load(f)


    def get_pravo_tokens(self, wallet):
        abi = pickle.loads(self.y["token"]["abi"])
        address = self.y["token"]["address"]
        contract = self.web3.eth.contract(abi=abi, address=address)


        # ret = contract.transact({'from': self.web3.eth.accounts[0]}).balanceOf(wallet)
        # print("balanceOf returned",ret)
        ret = contract.call().balanceOf(wallet)

        return ret

    def get_price(self, business):
        for afactory in self.y['factories']:
            if afactory["name"] == business:
                return (float(afactory["ether_price"]), int(afactory["token_price"]))
        return (-1, -1)

    def payment_ok(self, wallet):
        abi = pickle.loads(self.y["root"]["abi"])
        address = self.y["root"]["address"]
        contract = self.web3.eth.contract(abi=abi, address=address)

        try:
            ret = contract.call().paymentTimeDelta(wallet)
            print("payment_ok ", ret)
            return ret > 0 and ret < 1000   # take session timestamp into account
        except:
            return False

    def create_contract(self, business, wallet):
        abi = pickle.loads(self.y["root"]["abi"])
        address = self.y["root"]["address"]
        contract = self.web3.eth.contract(abi=abi, address=address)
        ret = contract.transact({'from': self.web3.eth.accounts[0]}).makeAction(business, wallet)
        return ret

    def get_contract_number(self, wallet):
        abi = pickle.loads(self.y["root"]["abi"])
        address = self.y["root"]["address"]
        contract = self.web3.eth.contract(abi=abi, address=address)
        ret = contract.call().getAddress(wallet)
        return (ret != '0x0000000000000000000000000000000000000000', ret)

    def start_job(self, contract_address, filename):
        abi = pickle.loads(self.y["action_chain"]["abi"])
        contract = self.web3.eth.contract(abi=abi, address=contract_address)
        contract.transact({'from': self.web3.eth.accounts[0]}).supplyInitialData([str(filename)])

    # removal concept ??
    def another_active_session(self, wallet, ip, salt):
        if wallet in self.known_session:
            if self.known_session['wallet'] != (ip, salt):
                return True
        else:
            self.known_session['wallet'] = (ip, salt)
        return False

    def root_contract(self):
        return self.y["root"]["address"]

    def get_current_stage(self, contract_address):
        abi = pickle.loads(self.y["action_chain"]["abi"])
        contract = self.web3.eth.contract(abi=abi, address=contract_address)
        ret = contract.call().stage()
        return ret

    def get_current_link_num(self, contract_address):
        abi = pickle.loads(self.y["action_chain"]["abi"])
        contract = self.web3.eth.contract(abi=abi, address=contract_address)
        ret = contract.call().link_num()
        return ret
