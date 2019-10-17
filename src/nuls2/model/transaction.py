import struct
import base64
import math
from binascii import hexlify, unhexlify
from datetime import datetime
from nuls2.model.data import (BaseNulsData, NulsDigestData,
                                        NulsSignature,
                                        write_with_length, read_by_length,
                                        writeUint48, readUint48,
                                        writeUint32, writeUint64,
                                        writeVarInt, hash_twice, VarInt,
                                        timestamp_from_time,
                                        address_from_hash,
                                        hash_from_address,
                                        PLACE_HOLDER, ADDRESS_LENGTH,
                                        HASH_LENGTH, COIN_UNIT,
                                        CHEAP_UNIT_FEE, UNIT_FEE, KB)
from nuls2.model.txtypes.register import TX_TYPES_REGISTER

class Coin(BaseNulsData):
    def __init__(self, data=None):
        self.address = None
        self.rawScript = None
        self.fromHash = None
        self.fromIndex = None
        self.na = None
        self.lockTime = None

        if data is not None:
            self.parse(data)

    def parse(self, buffer, cursor=0):
        pos, owner = read_by_length(buffer, cursor)
        cursor += pos
        if len(owner) == (HASH_LENGTH+1):
            val = (len(owner) - HASH_LENGTH)
            if (val > 1):
                fc = VarInt()
                fc.parse(owner, HASH_LENGTH)
                self.fromIndex = fc.value
                assert fc.originallyEncodedSize == val
            else:
                self.fromIndex = owner[-1]
            self.fromHash = owner[:HASH_LENGTH]
        elif len(owner) == ADDRESS_LENGTH:
            self.address = owner
        else:
            # ok, we have some script here
            self.rawScript = owner
            # tentative fix for now... Ugly.
            self.address = owner[2:ADDRESS_LENGTH+2] # it's either 2 or 3.
            # print(address_from_hash(owner[3:ADDRESS_LENGTH+3]))

        self.na = struct.unpack("Q", buffer[cursor:cursor+8])[0]
        cursor += 8
        self.lockTime = readUint48(buffer, cursor)
        cursor += 6
        return cursor

    def to_dict(self):
        val = {
            'value': self.na,
            'lockTime': self.lockTime
        }
        if self.rawScript is not None:
            val['owner'] = self.rawScript.hex()

        if self.address is not None:
            val['address'] = address_from_hash(self.address)
            val['addressHash'] = self.address

        if self.fromHash is not None:
            val['fromHash'] = self.fromHash.hex()
            val['fromIndex'] = self.fromIndex

        return val

    @classmethod
    def from_dict(cls, value):
        item = cls()
        item.address = value.get('address', None)
        item.assetsChainId = value.get('assetsChainId', None)
        item.assetsId = value.get('assetsId', None)
        
        item.fromIndex = value.get('fromIndex', None)
        item.lockTime = value.get('lockTime', 0)
        item.na = value.get('value', None)

        return item

    def __repr__(self):
        return "<UTXO Coin: {}: {} - {}>".format((self.address or self.fromHash).hex(), self.na, self.lockTime)

    def serialize(self):
        output = b""
        if self.rawScript is not None:
            output += write_with_length(self.rawScript)
        elif self.fromHash is not None:
            output += write_with_length(self.fromHash + bytes([self.fromIndex]))
        elif self.address is not None:
            output += write_with_length(self.address)
        else:
            raise ValueError("Either fromHash and fromId should be set or address.")

        output += struct.pack("Q", self.na)
        output += writeUint48(self.lockTime)
        return output

class CoinData(BaseNulsData):
    def __init__(self, data=None):
        self.from_count = None
        self.to_count = None
        self.inputs = list()
        self.outputs = list()

        #if data is not None:
        #    self.parse(data)

    async def parse(self, buffer, cursor=0):
        if buffer[cursor:cursor+4] == PLACE_HOLDER:
            return cursor+4

        fc = VarInt()
        fc.parse(buffer, cursor)
        self.from_count = fc.value
        cursor += fc.originallyEncodedSize
        self.inputs = list()
        for i in range(self.from_count):
            coin = Coin()
            cursor = coin.parse(buffer, cursor)
            self.inputs.append(coin)

        tc = VarInt()
        tc.parse(buffer, cursor)
        self.to_count = tc.value
        cursor += tc.originallyEncodedSize
        #self.to_count = buffer[cursor]
        self.outputs = list()
        for i in range(self.to_count):
            coin = Coin()
            cursor = coin.parse(buffer, cursor)
            self.outputs.append(coin)

        return cursor

    def get_fee(self):
        return (sum([i.na for i in self.inputs])
                - sum([o.na for o in self.outputs]))

    def get_output_sum(self):
        return sum([o.na for o in self.outputs])

    async def serialize(self):
        output = b""
        output += VarInt(len(self.inputs)).encode()
        for coin in self.inputs:
            output += coin.serialize()
        output += VarInt(len(self.outputs)).encode()
        for coin in self.outputs:
            output += coin.serialize()

        return output

class Transaction(BaseNulsData):
    def __init__(self):
        self.type = None
        self.time = None
        self.remark = None
        self.txData = None
        self.raw_coin_data = b''
        self.raw_tx_data = b''
        self.raw_signature = b''
        self.hash = None
        self.signature = None
        # self.scriptSig = None
        self.module_data = dict()
        # self.coin_data = CoinData()
        self.inputs = []
        self.outputs = []

    async def _parse_data(self, buffer, cursor=0):

        if self.type in TX_TYPES_REGISTER:
            cursor, self.module_data = await TX_TYPES_REGISTER[self.type].from_buffer(
                buffer, cursor)
        else:
            cursor += len(PLACE_HOLDER)

        return cursor

    async def _write_data(self):
        output = b""
        if self.type in TX_TYPES_REGISTER:
            output += await TX_TYPES_REGISTER[self.type].to_buffer(self.module_data)
            
        return output
    
    async def _write_coin_data(self):
        output = b""
        output += VarInt(len(self.inputs)).encode()
        for coin in self.inputs:
            output += write_with_length(hash_from_address(coin.get('address')))
            output += struct.pack("H", coin.get('assetsChainId'))
            output += struct.pack("H", coin.get('assetsId'))
            output += coin.get('amount').to_bytes(32, 'little')
            # output += struct.pack("Q", coin.get('amount'))
            output += write_with_length(bytes.fromhex(coin.get('nonce')))
            output += bytes([coin.get('locked')])
            
        output += VarInt(len(self.outputs)).encode()
        for coin in self.outputs:
            output += write_with_length(hash_from_address(coin.get('address')))
            output += struct.pack("H", coin.get('assetsChainId'))
            output += struct.pack("H", coin.get('assetsId'))
            # output += struct.pack("Q", coin.get('amount'))
            output += coin.get('amount').to_bytes(32, 'little')
            if coin.get('lockTime') == -1:
                output += bytes.fromhex("ffffffffffffffffff")
            else:
                output += struct.pack("Q", coin.get('lockTime'))

        return output
        
    async def _read_coin_data(self, buffer, cursor=0):
        if not len(buffer):
            return

        fc = VarInt()
        fc.parse(buffer, cursor)
        self.from_count = fc.value
        cursor += fc.originallyEncodedSize
        self.inputs = list()
        for i in range(self.from_count):
            coin = dict()
            pos, owner = read_by_length(buffer, cursor)
            cursor += pos
            coin['address'] = owner
            coin['assetsChainId'] = struct.unpack("H", buffer[cursor:cursor+2])[0]
            cursor += 2
            coin['assetsId'] = struct.unpack("H", buffer[cursor:cursor+2])[0]
            cursor += 2
            coin['amount'] = struct.unpack("Q", buffer[cursor:cursor+2])[0]
            cursor += 8
            
            pos, nonce = read_by_length(buffer, cursor)
            cursor += pos
            coin['address'] = owner
            
            coin['locked'] = buffer[pos]
            pos += 1
            
            self.inputs.append(coin)

        tc = VarInt()
        tc.parse(buffer, cursor)
        self.to_count = tc.value
        cursor += tc.originallyEncodedSize
        #self.to_count = buffer[cursor]
        self.outputs = list()
        for i in range(self.to_count):
            coin = Coin()
            cursor = coin.parse(buffer, cursor)
            self.outputs.append(coin)

        return cursor
        st_cursor = cursor
        self.type = struct.unpack("H", buffer[cursor:cursor+2])[0]
        cursor += 2
        self.time = struct.unpack("I", buffer[cursor:cursor+2])[0]
        # self.time = readUint48(buffer, cursor)
        cursor += 4

    async def get_hash(self):
        # if self.hash_varint:
        #     values = bytes((self.type,)) \
        #             + bytes((255,)) + writeUint64(self.time)
        # else:
        #     values = struct.pack("H", self.type) \
        #             + writeUint48(self.time)

        # values += (write_with_length(self.remark)
        #            + (await self._write_data())
        #            + (await self.coin_data.serialize()))
        values = await self.serialize(for_hash=True)

        hash_bytes = hash_twice(values)
        # hash = NulsDigestData(data=hash_bytes, alg_type=0)
        return hash_bytes

    async def parse(self, buffer, cursor=0):
        st_cursor = cursor
        self.type = struct.unpack("H", buffer[cursor:cursor+2])[0]
        cursor += 2
        self.time = struct.unpack("I", buffer[cursor:cursor+2])[0]
        # self.time = readUint48(buffer, cursor)
        cursor += 4


        st2_cursor = cursor

        pos, self.remark = read_by_length(buffer, cursor, check_size=True)
        cursor += pos
        
        cursor, self.raw_tx_data = read_by_length(buffer, cursor, check_size=True)
        cursor, self.raw_coin_data = read_by_length(buffer, cursor, check_size=True)
        cursor, self.raw_signature = read_by_length(buffer, cursor, check_size=True)
        self.size = cursor - st_cursor
        

        # cursor = await self._parse_data(buffer, cursor)

        # self.coin_data = CoinData()
        # cursor = await self.coin_data.parse(buffer, cursor)
        # med_cursor = cursor

        # if self.hash_varint:
        #     values = bytes((self.type,)) \
        #             + bytes((255,)) + writeUint64(self.time)
        # else:
        #     values = struct.pack("H", self.type) \
        #             + writeUint48(self.time)

        # values += buffer[st2_cursor:med_cursor]

        # self.hash_bytes = hash_twice(values)
        # self.hash = NulsDigestData(data=self.hash_bytes, alg_type=0)

        # pos, self.scriptSig = read_by_length(buffer, cursor, check_size=True)
        # cursor += pos
        # end_cursor = cursor
        # self.size = end_cursor - st_cursor

        return cursor
    
    async def serialize(self, for_hash=False, update_coins=True, update_data=True):
        if update_data and self.type in TX_TYPES_REGISTER:
            self.raw_tx_data = await self._write_data()
        if update_coins:
            self.raw_coin_data = await self._write_coin_data()
            
        output = b""
        output += struct.pack("H", self.type)
        output += struct.pack("I", self.time)
        output += write_with_length(self.remark)
        output += write_with_length(self.raw_tx_data)
        output += write_with_length(self.raw_coin_data)
        if not for_hash:
            output += write_with_length(self.raw_signature)
        # output += write_with_length(await self.coin_data.serialize())
        # output += self.scriptSig is not None and write_with_length(self.scriptSig) or PLACE_HOLDER
        return output


    async def to_dict(self):
        try:
            remark = self.remark and self.remark.decode('utf-8') or None
        except UnicodeDecodeError:
            remark = base64.b64encode(self.remark).decode("utf-8")

        return {
            'hash': str(self.hash),
            'type': self.type,
            'time': self.time,
            'blockHeight': self.height,
            'fee': self.type != 1 and self.coin_data.get_fee() or 0,
            'remark': remark,
            'scriptSig': self.scriptSig and self.scriptSig.hex() or None,
            'size': self.size,
            'txData': self.module_data,
            'coinFroms': self.inputs,
            'coinTos': self.outputs
        }

    @classmethod
    async def from_dict(cls, value):
        item = cls()
        #item.hash = value.get('hash', '').encode('UTF-8')
        item.type = value['type']
        item.time = value.get('time')
        if item.time is None:
            item.time = timestamp_from_time(datetime.now())
        item.height = value.get('height') # optionnal, when creating a tx.
        item.remark = value.get('remark', b'')
        item.scriptSig = value.get('scriptSig')
        item.size = value.get('size')
        item.module_data = value.get('txData') # this should be fixed.
        
        item.inputs = value.get('coinFroms', [])
        item.outputs = value.get('coinTos', [])

        # for input in value.get('coinFroms'):
        #     item.coin_data.inputs.append(Coin.from_dict(input))
        # item.coin_data.from_count = len(item.coin_data.inputs)

        # for output in value.get('coinTos'):
        #     item.coin_data.outputs.append(Coin.from_dict(output))
        # item.coin_data.to_count = len(item.coin_data.outputs)

        return item

    async def sign_tx(self, pri_key):
        self.signature = NulsSignature.sign_data(
            pri_key, await self.get_hash())
        self.raw_signature = self.signature.serialize()

    async def run_processor(self):
        return await process_tx(self, step="pre")

    async def calculate_fee(self):
        size = len(await self.serialize())
        unit_fee = UNIT_FEE
        if self.type in [2, 10, 16]:
            unit_fee = CHEAP_UNIT_FEE

        fee = unit_fee * math.ceil(size / KB)  # per kb

        # if size % KB > 0:
        #     # why is it needed, to be sure we have at least the fee ?
        #     # or am I doing a bad port from java, where they work with int
        #     # and not mutable ?
        #     fee += unit_fee

        return fee
